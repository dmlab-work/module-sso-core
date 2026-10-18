<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Model\Oidc;

/**
 * Immutable OIDC provider metadata parsed from the discovery document.
 */
class ProviderMetadata
{
    /**
     * Build provider metadata from the discovered endpoints.
     *
     * @param string $issuer
     * @param string $authorizationEndpoint
     * @param string $tokenEndpoint
     * @param string $jwksUri
     */
    public function __construct(
        private readonly string $issuer,
        private readonly string $authorizationEndpoint,
        private readonly string $tokenEndpoint,
        private readonly string $jwksUri
    ) {
    }

    /**
     * Get the issuer identifier.
     */
    public function getIssuer(): string
    {
        return $this->issuer;
    }

    /**
     * Get the authorization endpoint URL.
     */
    public function getAuthorizationEndpoint(): string
    {
        return $this->authorizationEndpoint;
    }

    /**
     * Get the token endpoint URL.
     */
    public function getTokenEndpoint(): string
    {
        return $this->tokenEndpoint;
    }

    /**
     * Get the JWKS URI.
     */
    public function getJwksUri(): string
    {
        return $this->jwksUri;
    }
}
