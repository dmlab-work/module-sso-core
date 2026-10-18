<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Api\Data;

/**
 * Normalized identity produced by the OIDC engine from validated IdP claims.
 *
 * Provider-agnostic: presets map their claim shape onto this contract so every
 * SSO product consumes the same identity regardless of IdP.
 */
interface IdentityInterface
{
    /**
     * Stable, unique subject identifier from the IdP (the `sub` claim).
     */
    public function getSubjectId(): string;

    /**
     * Email address, or null when the IdP did not release it.
     */
    public function getEmail(): ?string;

    /**
     * Whether the IdP asserted the email as verified; false when there is no email or no assertion.
     */
    public function isEmailVerified(): bool;

    /**
     * Display name, or null when the IdP did not release it.
     */
    public function getName(): ?string;

    /**
     * Group memberships from the IdP; empty array when none.
     *
     * @return string[]
     */
    public function getGroups(): array;
}
