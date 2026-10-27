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
     * @param string[] $tokenEndpointAuthMethodsSupported
     * @param string[] $idTokenSigningAlgValuesSupported
     * @param bool $authorizationResponseIssParameterSupported
     */
    public function __construct(
        private readonly string $issuer,
        private readonly string $authorizationEndpoint,
        private readonly string $tokenEndpoint,
        private readonly string $jwksUri,
        private readonly array $tokenEndpointAuthMethodsSupported = [],
        private readonly array $idTokenSigningAlgValuesSupported = [],
        private readonly bool $authorizationResponseIssParameterSupported = false
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

    /**
     * Get `token_endpoint_auth_methods_supported`; empty when not advertised.
     *
     * @return string[]
     */
    public function getTokenEndpointAuthMethodsSupported(): array
    {
        return $this->tokenEndpointAuthMethodsSupported;
    }

    /**
     * Get `id_token_signing_alg_values_supported`; empty when not advertised.
     *
     * @return string[]
     */
    public function getIdTokenSigningAlgValuesSupported(): array
    {
        return $this->idTokenSigningAlgValuesSupported;
    }

    /**
     * Whether the IdP sends `iss` in authorization responses (RFC 9207).
     */
    public function isAuthorizationResponseIssParameterSupported(): bool
    {
        return $this->authorizationResponseIssParameterSupported;
    }
}
