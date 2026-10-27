<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Model\Oidc;

use DmLab\SsoCore\Exception\DiscoveryException;
use Magento\Framework\Cache\FrontendInterface;
use Magento\Framework\HTTP\ClientFactory;
use Magento\Framework\HTTP\ClientInterface;
use Magento\Framework\Serialize\SerializerInterface;

/**
 * Fetches and caches an IdP's `.well-known/openid-configuration` document and
 * exposes the endpoints the engine needs (issuer, authorization, token, JWKS).
 */
class DiscoveryClient
{
    private const CACHE_PREFIX = 'dmlab_ssocore_oidc_discovery_';

    private const WELL_KNOWN_SUFFIX = '/.well-known/openid-configuration';

    /**
     * Discovery keys required to drive the OIDC flow.
     */
    private const REQUIRED_KEYS = [
        'issuer',
        'authorization_endpoint',
        'token_endpoint',
        'jwks_uri',
    ];

    /**
     * Endpoints the engine dereferences over HTTP; all must be HTTPS to prevent
     * SSRF and client-secret leakage from a spoofed or misconfigured document.
     */
    private const HTTPS_ENDPOINT_KEYS = [
        'authorization_endpoint',
        'token_endpoint',
        'jwks_uri',
    ];

    /**
     * Inject HTTP client factory, cache, serializer, cache lifetime, and timeouts (seconds).
     *
     * @param ClientFactory $httpClientFactory
     * @param FrontendInterface $cache
     * @param SerializerInterface $serializer
     * @param int $cacheLifetime
     * @param int $connectTimeout
     * @param int $timeout
     */
    public function __construct(
        private readonly ClientFactory $httpClientFactory,
        private readonly FrontendInterface $cache,
        private readonly SerializerInterface $serializer,
        private readonly int $cacheLifetime = 3600,
        private readonly int $connectTimeout = 5,
        private readonly int $timeout = 10
    ) {
    }

    /**
     * Resolve provider metadata for the given discovery URL, using the cache when warm.
     *
     * With `$requireIssuerMatch`, the URL must end in `/.well-known/openid-configuration` and be
     * prefixed by the document's `issuer`, minus a trailing `/` (OIDC Discovery §4.1, §4.3).
     *
     * @param string $discoveryUrl
     * @param bool $requireIssuerMatch
     * @throws DiscoveryException
     */
    public function discover(string $discoveryUrl, bool $requireIssuerMatch = true): ProviderMetadata
    {
        $this->assertHttps($discoveryUrl, 'discovery URL');

        $cacheId = self::CACHE_PREFIX . hash('sha256', $discoveryUrl);

        $cached = $this->cache->load($cacheId);
        if (is_string($cached) && $cached !== '') {
            $metadata = $this->parse($cached);
            if ($requireIssuerMatch) {
                $this->assertIssuerMatches($discoveryUrl, $metadata->getIssuer());
            }

            return $metadata;
        }

        $body = $this->fetch($discoveryUrl);
        $metadata = $this->parse($body);
        if ($requireIssuerMatch) {
            $this->assertIssuerMatches($discoveryUrl, $metadata->getIssuer());
        }
        $this->cache->save($body, $cacheId, [], $this->cacheLifetime);

        return $metadata;
    }

    /**
     * Fetch the raw discovery document over HTTP.
     *
     * @param string $discoveryUrl
     * @throws DiscoveryException
     */
    private function fetch(string $discoveryUrl): string
    {
        $httpClient = $this->createHttpClient();
        try {
            $httpClient->get($discoveryUrl);
        } catch (\Throwable $e) {
            throw new DiscoveryException(
                'Failed to fetch OIDC discovery document: ' . $e->getMessage(),
                0,
                $e
            );
        }

        $status = (int)$httpClient->getStatus();
        if ($status !== 200) {
            throw new DiscoveryException(
                sprintf('OIDC discovery request returned HTTP %d for "%s".', $status, $discoveryUrl)
            );
        }

        return (string)$httpClient->getBody();
    }

    /**
     * Create a fresh, bounded, HTTPS-only HTTP client for one request.
     */
    private function createHttpClient(): ClientInterface
    {
        $client = $this->httpClientFactory->create();
        $client->setTimeout($this->timeout);
        $client->setOption(CURLOPT_CONNECTTIMEOUT, $this->connectTimeout);
        $client->setOption(CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);

        return $client;
    }

    /**
     * Parse and validate the discovery document into provider metadata.
     *
     * @param string $body
     * @throws DiscoveryException
     */
    private function parse(string $body): ProviderMetadata
    {
        try {
            $data = $this->serializer->unserialize($body);
        } catch (\Throwable $e) {
            throw new DiscoveryException('OIDC discovery document is not valid JSON.', 0, $e);
        }

        if (!is_array($data)) {
            throw new DiscoveryException('OIDC discovery document is not a JSON object.');
        }

        foreach (self::REQUIRED_KEYS as $key) {
            if (!isset($data[$key]) || !is_string($data[$key]) || $data[$key] === '') {
                throw new DiscoveryException(
                    sprintf('OIDC discovery document is missing "%s".', $key)
                );
            }
        }

        foreach (self::HTTPS_ENDPOINT_KEYS as $key) {
            $this->assertHttps($data[$key], $key);
        }
        $this->assertIssuerIdentifier($data['issuer']);

        return new ProviderMetadata(
            $data['issuer'],
            $data['authorization_endpoint'],
            $data['token_endpoint'],
            $data['jwks_uri'],
            $this->stringList($data, 'token_endpoint_auth_methods_supported'),
            $this->stringList($data, 'id_token_signing_alg_values_supported'),
            ($data['authorization_response_iss_parameter_supported'] ?? false) === true
        );
    }

    /**
     * Read an optional JSON array of strings; non-string members and non-arrays are dropped.
     *
     * @param array<string,mixed> $data
     * @param string $key
     * @return string[]
     */
    private function stringList(array $data, string $key): array
    {
        $value = $data[$key] ?? null;
        if (!is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, static fn($item) => is_string($item) && $item !== ''));
    }

    /**
     * Assert the issuer is an https URL without query or fragment (OIDC Discovery §3).
     *
     * @param string $issuer
     * @throws DiscoveryException
     */
    private function assertIssuerIdentifier(string $issuer): void
    {
        $this->assertHttps($issuer, 'issuer');
        if (str_contains($issuer, '?') || str_contains($issuer, '#')) {
            throw new DiscoveryException(
                sprintf('OIDC issuer must not contain a query or fragment: "%s".', $issuer)
            );
        }
    }

    /**
     * Assert the issuer equals the discovery URL prefix (OIDC Discovery §4.3).
     *
     * @param string $discoveryUrl
     * @param string $issuer
     * @throws DiscoveryException when the URL is non-standard or the issuer differs
     */
    private function assertIssuerMatches(string $discoveryUrl, string $issuer): void
    {
        if (!str_ends_with($discoveryUrl, self::WELL_KNOWN_SUFFIX)) {
            throw new DiscoveryException(sprintf(
                'OIDC discovery URL "%s" does not end with "%s", so its issuer cannot be verified.',
                $discoveryUrl,
                self::WELL_KNOWN_SUFFIX
            ));
        }

        $expected = substr($discoveryUrl, 0, -strlen(self::WELL_KNOWN_SUFFIX));
        // §4.1: a trailing slash is removed from the issuer before the suffix is appended.
        if (rtrim($issuer, '/') !== $expected) {
            throw new DiscoveryException(
                sprintf('OIDC discovery issuer "%s" does not match expected "%s".', $issuer, $expected)
            );
        }
    }

    /**
     * Assert a URL uses the HTTPS scheme before it is dereferenced.
     *
     * @param string $url
     * @param string $label
     * @throws DiscoveryException
     */
    private function assertHttps(string $url, string $label): void
    {
        if (!str_starts_with(strtolower($url), 'https://')) {
            throw new DiscoveryException(
                sprintf('OIDC %s must use HTTPS: "%s".', $label, $url)
            );
        }
    }
}
