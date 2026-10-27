<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Api\Data;

/**
 * One-time authorization state the consumer must persist between the redirect to
 * the IdP and the callback: `state` (CSRF), `nonce` (replay), the PKCE
 * `code_verifier` needed to redeem the authorization code at the token endpoint,
 * and the issuer the request was sent to (mix-up defense, RFC 9700 §4.4).
 */
interface AuthorizationStateInterface
{
    /**
     * Opaque anti-CSRF token echoed back by the IdP on the callback.
     */
    public function getState(): string;

    /**
     * Anti-replay value bound into the ID token and checked on the callback.
     */
    public function getNonce(): string;

    /**
     * PKCE `code_verifier` proving the client that started the flow completes it.
     */
    public function getCodeVerifier(): string;

    /**
     * Issuer identifier of the IdP the request was sent to; empty when unknown.
     */
    public function getIssuer(): string;
}
