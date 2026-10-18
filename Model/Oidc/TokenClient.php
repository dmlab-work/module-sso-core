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
 */
class TokenClient
{
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
     * @throws TokenException
     */
    public function exchangeCode(
        string $tokenEndpoint,
        string $code,
        string $redirectUri,
        string $clientId,
        string $codeVerifier,
        ?string $clientSecret = null
    ): TokenResponse {
        $params = [
            'grant_type' => self::GRANT_TYPE,
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'client_id' => $clientId,
            'code_verifier' => $codeVerifier,
        ];
        if ($clientSecret !== null && $clientSecret !== '') {
            $params['client_secret'] = $clientSecret;
        }

        $httpClient = $this->createHttpClient();
        $httpClient->addHeader('Accept', 'application/json');

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
