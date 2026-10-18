<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Model\Oidc;

/**
 * Immutable token endpoint response. `id_token` is required for OIDC; the rest
 * are optional per the grant/provider.
 */
class TokenResponse
{
    /**
     * Build the token response from the parsed token endpoint fields.
     *
     * @param string $idToken
     * @param string|null $accessToken
     * @param string|null $tokenType
     * @param int|null $expiresIn
     * @param string|null $refreshToken
     * @param string|null $scope
     */
    public function __construct(
        private readonly string $idToken,
        private readonly ?string $accessToken = null,
        private readonly ?string $tokenType = null,
        private readonly ?int $expiresIn = null,
        private readonly ?string $refreshToken = null,
        private readonly ?string $scope = null
    ) {
    }

    /**
     * Get the OIDC ID token.
     */
    public function getIdToken(): string
    {
        return $this->idToken;
    }

    /**
     * Get the access token, if present.
     */
    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }

    /**
     * Get the token type, if present.
     */
    public function getTokenType(): ?string
    {
        return $this->tokenType;
    }

    /**
     * Get the token lifetime in seconds, if present.
     */
    public function getExpiresIn(): ?int
    {
        return $this->expiresIn;
    }

    /**
     * Get the refresh token, if present.
     */
    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }

    /**
     * Get the granted scope, if present.
     */
    public function getScope(): ?string
    {
        return $this->scope;
    }
}
