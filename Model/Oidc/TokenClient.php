<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Model\Oidc;

use DmLab\SsoCore\Exception\TokenException;
use Magento\Framework\HTTP\ClientFactory;
use Magento\Framework\HTTP\ClientInterface;
use Magento\Framework\Serialize\SerializerInterface;

/**
 * Exchanges an authorization code for tokens at the IdP's `token_endpoint`
 * (authorization-code + PKCE grant). Returns the parsed token set including the
 * `id_token` the validator consumes.
 *
 * A confidential client authenticates with `client_secret_basic` unless the IdP advertises
 * only `client_secret_post`; a client without a secret sends just `client_id`.
 */
class TokenClient
{
    public const AUTH_METHOD_BASIC = 'client_secret_basic';
    public const AUTH_METHOD_POST = 'client_secret_post';

    private const GRANT_TYPE = 'authorization_code';

    /**
     * Inject the HTTP client factory, JSON serializer, and timeouts (seconds).
     *
     * @param ClientFactory $httpClientFactory
     * @param SerializerInterface $serializer
     * @param int $connectTimeout
     * @param int $timeout
     */
    public function __construct(
        private readonly ClientFactory $httpClientFactory,
        private readonly SerializerInterface $serializer,
        private readonly int $connectTimeout = 5,
        private readonly int $timeout = 10
    ) {
    }

    /**
     * Exchange an authorization code for tokens at the token endpoint.
     *
     * @param string $tokenEndpoint
     * @param string $code
     * @param string $redirectUri
     * @param string $clientId
     * @param string $codeVerifier
     * @param string|null $clientSecret
     * @param string[] $authMethodsSupported discovery `token_endpoint_auth_methods_supported`
     * @throws TokenException
     */
    public function exchangeCode(
        string $tokenEndpoint,
        string $code,
        string $redirectUri,
        string $clientId,
        string $codeVerifier,
        ?string $clientSecret = null,
        array $authMethodsSupported = []
    ): TokenResponse {
        $params = [
            'grant_type' => self::GRANT_TYPE,
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $codeVerifier,
        ];

        $httpClient = $this->createHttpClient();
        $httpClient->addHeader('Accept', 'application/json');

        $authMethod = $this->selectAuthMethod($clientSecret, $authMethodsSupported);
        if ($authMethod === self::AUTH_METHOD_BASIC) {
            // RFC 6749 §2.3.1: credentials are form-encoded before base64. rawurlencode keeps `~`
            // literal, so IdPs that skip the decode still accept typical (Entra) secrets.
            $httpClient->addHeader(
                'Authorization',
                'Basic ' . base64_encode(rawurlencode($clientId) . ':' . rawurlencode((string)$clientSecret))
            );
        } else {
            $params['client_id'] = $clientId;
            if ($authMethod === self::AUTH_METHOD_POST) {
                $params['client_secret'] = $clientSecret;
            }
        }

        try {
            $httpClient->post($tokenEndpoint, $params);
        } catch (\Throwable $e) {
            throw new TokenException('Failed to reach the OIDC token endpoint: ' . $e->getMessage(), 0, $e);
        }

        $status = (int)$httpClient->getStatus();
        $body = (string)$httpClient->getBody();
        $data = $this->decode($body);

        if ($status !== 200) {
            throw new TokenException($this->describeError($status, $data));
        }

        if (!isset($data['id_token']) || !is_string($data['id_token']) || $data['id_token'] === '') {
            throw new TokenException('OIDC token response is missing "id_token".');
        }

        return new TokenResponse(
            $data['id_token'],
            $this->stringOrNull($data, 'access_token'),
            $this->stringOrNull($data, 'token_type'),
            isset($data['expires_in']) && is_numeric($data['expires_in']) ? (int)$data['expires_in'] : null,
            $this->stringOrNull($data, 'refresh_token'),
            $this->stringOrNull($data, 'scope')
        );
    }

    /**
     * Pick the client authentication method; null for a client without a secret.
     *
     * @param string|null $clientSecret
     * @param string[] $supported
     * @throws TokenException when the IdP advertises neither secret-based method
     */
    private function selectAuthMethod(?string $clientSecret, array $supported): ?string
    {
        if ($clientSecret === null || $clientSecret === '') {
            return null;
        }
        // OIDC Discovery §3: an absent list means client_secret_basic.
        if ($supported === [] || in_array(self::AUTH_METHOD_BASIC, $supported, true)) {
            return self::AUTH_METHOD_BASIC;
        }
        if (in_array(self::AUTH_METHOD_POST, $supported, true)) {
            return self::AUTH_METHOD_POST;
        }

        throw new TokenException(sprintf(
            'The OIDC token endpoint supports neither client_secret_basic nor client_secret_post (advertised: %s).',
            implode(', ', $supported)
        ));
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
     * Decode the token endpoint JSON response.
     *
     * @param string $body
     * @return array<string, mixed>
     * @throws TokenException
     */
    private function decode(string $body): array
    {
        try {
            $data = $this->serializer->unserialize($body);
        } catch (\Throwable $e) {
            throw new TokenException('OIDC token response is not valid JSON.', 0, $e);
        }

        if (!is_array($data)) {
            throw new TokenException('OIDC token response is not a JSON object.');
        }

        return $data;
    }

    /**
     * Build an error message from an unsuccessful token response.
     *
     * @param int $status
     * @param array<string,mixed> $data
     */
    private function describeError(int $status, array $data): string
    {
        $error = isset($data['error']) && is_string($data['error']) ? $data['error'] : 'unknown_error';
        $description = isset($data['error_description']) && is_string($data['error_description'])
            ? ': ' . $data['error_description']
            : '';

        return sprintf('OIDC token endpoint returned HTTP %d (%s)%s.', $status, $error, $description);
    }

    /**
     * Return a string value for the key, or null when absent/non-string.
     *
     * @param array<string,mixed> $data
     * @param string $key
     */
    private function stringOrNull(array $data, string $key): ?string
    {
        return isset($data[$key]) && is_string($data[$key]) ? $data[$key] : null;
    }
}
