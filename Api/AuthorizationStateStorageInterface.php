<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Api;

use DmLab\SsoCore\Api\Data\AuthorizationStateInterface;

/**
 * Storage contract for the per-request authorization state (state, nonce, PKCE
 * verifier). The engine builds the state; the consuming product persists it
 * (session, cache, ...) before the redirect and reloads it on the callback.
 *
 * The core ships no implementation — persistence is a product concern.
 */
interface AuthorizationStateStorageInterface
{
    /**
     * Persist the authorization state ahead of the redirect to the IdP.
     *
     * @param AuthorizationStateInterface $state
     */
    public function save(AuthorizationStateInterface $state): void;

    /**
     * Load and invalidate the one-time state matching the callback value.
     *
     * Returns null when unknown/expired; a second call for the same value must
     * return null (replay protection).
     *
     * @param string $state
     */
    public function consume(string $state): ?AuthorizationStateInterface;
}
