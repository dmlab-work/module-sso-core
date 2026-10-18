<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Model\Oidc;

use Magento\Framework\Math\Random;

/**
 * Builds an authorization-code + PKCE authorization request: generates `state`,
 * `nonce`, and the PKCE verifier/challenge (`S256`), then assembles the redirect
 * URL from the discovered authorization endpoint and the preset's scopes.
 */
class AuthorizationRequestFactory
{
    private const RESPONSE_TYPE = 'code';
    private const CODE_CHALLENGE_METHOD = 'S256';

    /**
     * 32 random bytes → 43-char base64url string, within the PKCE verifier range
     * (43–128 chars) and giving ample entropy for `state`/`nonce`.
     */
    private const RANDOM_BYTES = 32;

    /**
     * Params owned by the factory; presets must not override them.
     */
    private const RESERVED_PARAMS = [
        'response_type',
        'client_id',
        'redirect_uri',
        'scope',
        'state',
        'nonce',
        'code_challenge',
        'code_challenge_method',
    ];

    /**
     * Inject the secure random generator.
     *
     * @param Random $random
     */
    public function __construct(
        private readonly Random $random
    ) {
    }

    /**
     * Build an authorization-code + PKCE authorization request.
     *
     * @param string $authorizationEndpoint
     * @param string $clientId
     * @param string $redirectUri
     * @param string[] $scopes
     * @param array<string,string> $extraParams preset params, e.g. from AuthorizationParamsProviderInterface
     * @throws \InvalidArgumentException on a reserved key or non-string value in $extraParams
     */
    public function create(
        string $authorizationEndpoint,
        string $clientId,
        string $redirectUri,
        array $scopes,
        array $extraParams = []
    ): AuthorizationRequest {
        $this->assertExtraParams($extraParams);

        $state = $this->randomToken();
        $nonce = $this->randomToken();
        $codeVerifier = $this->randomToken();

        $params = [
            'response_type' => self::RESPONSE_TYPE,
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'scope' => implode(' ', $scopes),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $this->deriveChallenge($codeVerifier),
            'code_challenge_method' => self::CODE_CHALLENGE_METHOD,
        ] + $extraParams;

        $separator = str_contains($authorizationEndpoint, '?') ? '&' : '?';
        $url = $authorizationEndpoint . $separator
            . http_build_query($params, '', '&', PHP_QUERY_RFC3986);

        return new AuthorizationRequest($url, $state, $nonce, $codeVerifier);
    }

    /**
     * Reject extra params that override core params or are not strings.
     *
     * @param array<mixed> $extraParams
     * @throws \InvalidArgumentException
     */
    private function assertExtraParams(array $extraParams): void
    {
        foreach ($extraParams as $key => $value) {
            if (in_array((string)$key, self::RESERVED_PARAMS, true)) {
                throw new \InvalidArgumentException(
                    sprintf('Authorization param "%s" is reserved and cannot be overridden.', $key)
                );
            }
            if (!is_string($value)) {
                throw new \InvalidArgumentException(
                    sprintf('Authorization param "%s" must be a string.', $key)
                );
            }
        }
    }

    /**
     * Derive the S256 PKCE code challenge from the verifier.
     *
     * @param string $codeVerifier
     */
    private function deriveChallenge(string $codeVerifier): string
    {
        return $this->base64UrlEncode(hash('sha256', $codeVerifier, true));
    }

    /**
     * Generate a base64url random token.
     */
    private function randomToken(): string
    {
        return $this->base64UrlEncode($this->random->getRandomBytes(self::RANDOM_BYTES));
    }

    /**
     * Base64url-encode the given bytes without padding.
     *
     * @param string $bytes
     */
    private function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
