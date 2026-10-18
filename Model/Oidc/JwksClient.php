<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Model\Oidc;

use DmLab\SsoCore\Exception\IdTokenValidationException;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Magento\Framework\Cache\FrontendInterface;
use Magento\Framework\HTTP\ClientFactory;
use Magento\Framework\HTTP\ClientInterface;

/**
 * Fetches and caches an IdP's JWKS document (`jwks_uri`) and returns it as a
 * `JWKSet` for signature verification. `getKeySetForToken()` refetches once
 * (rate-limited) when the token's `kid` is missing from the cached set, so IdP
 * key rotation does not break logins until the cache expires.
 */
class JwksClient
{
    private const CACHE_PREFIX = 'dmlab_ssocore_oidc_jwks_';
    private const REFETCH_PREFIX = 'dmlab_ssocore_oidc_jwks_refetch_';

    /**
     * Inject the HTTP client factory, cache, cache lifetime, timeouts, and refetch cooldown (seconds).
     *
     * @param ClientFactory $httpClientFactory
     * @param FrontendInterface $cache
     * @param int $cacheLifetime
     * @param int $connectTimeout
     * @param int $timeout
     * @param int $refetchCooldown
     */
    public function __construct(
        private readonly ClientFactory $httpClientFactory,
        private readonly FrontendInterface $cache,
        private readonly int $cacheLifetime = 3600,
        private readonly int $connectTimeout = 5,
        private readonly int $timeout = 10,
        private readonly int $refetchCooldown = 60
    ) {
    }

    /**
     * Resolve the IdP JWKS as a key set, using the cache when warm.
     *
     * @param string $jwksUri
     * @throws IdTokenValidationException
     */
    public function getKeySet(string $jwksUri): JWKSet
    {
        return $this->load($jwksUri)[0];
    }

    /**
     * Resolve the IdP JWKS for an ID token, refetching when its `kid` is unknown.
     *
     * At most one refetch per `refetchCooldown`; during cooldown the cached set is returned.
     *
     * @param string $jwksUri
     * @param string $idToken
     * @throws IdTokenValidationException
     */
    public function getKeySetForToken(string $jwksUri, string $idToken): JWKSet
    {
        [$keySet, $fromCache] = $this->load($jwksUri);

        $kid = $this->extractKid($idToken);
        if ($kid === null || !$fromCache || $keySet->has($kid)) {
            return $keySet;
        }

        $markerId = self::REFETCH_PREFIX . hash('sha256', $jwksUri);
        if ($this->cache->load($markerId) !== false) {
            return $keySet;
        }
        // Marker is set before the fetch so a failing IdP is not hammered either.
        $this->cache->save('1', $markerId, [], $this->refetchCooldown);

        return $this->refresh($jwksUri);
    }

    /**
     * Load the key set from cache or HTTP; the flag tells whether it came from cache.
     *
     * @param string $jwksUri
     * @return array{0: JWKSet, 1: bool}
     * @throws IdTokenValidationException
     */
    private function load(string $jwksUri): array
    {
        $cached = $this->cache->load($this->cacheId($jwksUri));
        if (is_string($cached) && $cached !== '') {
            return [$this->parse($cached), true];
        }

        return [$this->refresh($jwksUri), false];
    }

    /**
     * Fetch, parse, and cache the JWKS document.
     *
     * @param string $jwksUri
     * @throws IdTokenValidationException
     */
    private function refresh(string $jwksUri): JWKSet
    {
        $body = $this->fetch($jwksUri);
        $keySet = $this->parse($body);
        $this->cache->save($body, $this->cacheId($jwksUri), [], $this->cacheLifetime);

        return $keySet;
    }

    /**
     * Cache id of the JWKS document for a URI.
     *
     * @param string $jwksUri
     */
    private function cacheId(string $jwksUri): string
    {
        return self::CACHE_PREFIX . hash('sha256', $jwksUri);
    }

    /**
     * Read `kid` from the unverified protected header (key routing only); null when absent or malformed.
     *
     * @param string $idToken
     */
    private function extractKid(string $idToken): ?string
    {
        try {
            $signature = (new CompactSerializer())->unserialize($idToken)->getSignature(0);
        } catch (\Throwable $e) {
            return null;
        }

        $kid = $signature->hasProtectedHeaderParameter('kid')
            ? $signature->getProtectedHeaderParameter('kid')
            : null;

        return is_string($kid) && $kid !== '' ? $kid : null;
    }

    /**
     * Fetch the raw JWKS document over HTTP.
     *
     * @param string $jwksUri
     * @throws IdTokenValidationException
     */
    private function fetch(string $jwksUri): string
    {
        $httpClient = $this->createHttpClient();
        try {
            $httpClient->get($jwksUri);
        } catch (\Throwable $e) {
            throw new IdTokenValidationException('Failed to fetch JWKS document: ' . $e->getMessage(), 0, $e);
        }

        $status = (int)$httpClient->getStatus();
        if ($status !== 200) {
            throw new IdTokenValidationException(
                sprintf('JWKS request returned HTTP %d for "%s".', $status, $jwksUri)
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
     * Parse the JWKS document into a key set.
     *
     * @param string $body
     * @throws IdTokenValidationException
     */
    private function parse(string $body): JWKSet
    {
        try {
            return JWKSet::createFromJson($body);
        } catch (\Throwable $e) {
            throw new IdTokenValidationException('JWKS document is malformed.', 0, $e);
        }
    }
}
