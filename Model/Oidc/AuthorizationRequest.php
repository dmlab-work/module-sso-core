<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Model\Oidc;

use DmLab\SsoCore\Api\Data\AuthorizationStateInterface;

/**
 * Immutable result of building an OIDC authorization request: the ready-to-use
 * redirect URL plus the one-time state the consumer persists for the callback.
 */
class AuthorizationRequest implements AuthorizationStateInterface
{
    /**
     * Build the authorization request from its URL and one-time state.
     *
     * @param string $url
     * @param string $state
     * @param string $nonce
     * @param string $codeVerifier
     */
    public function __construct(
        private readonly string $url,
        private readonly string $state,
        private readonly string $nonce,
        private readonly string $codeVerifier
    ) {
    }

    /**
     * Absolute authorization URL to redirect the user agent to.
     */
    public function getUrl(): string
    {
        return $this->url;
    }

    /**
     * Get the anti-CSRF state token.
     */
    public function getState(): string
    {
        return $this->state;
    }

    /**
     * Get the anti-replay nonce.
     */
    public function getNonce(): string
    {
        return $this->nonce;
    }

    /**
     * Get the PKCE code verifier.
     */
    public function getCodeVerifier(): string
    {
        return $this->codeVerifier;
    }
}
