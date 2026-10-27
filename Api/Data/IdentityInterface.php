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
     * Issuer identifier of the IdP that asserted the identity (the validated `iss` claim).
     *
     * `sub` is unique only per issuer: bind accounts on the (issuer, subject) pair.
     */
    public function getIssuer(): string;

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

    /**
     * Whether the IdP sent the claim as a distributed/aggregated claim.
     *
     * Listed in `_claim_names` (OIDC Core §5.6.2) instead of inline, so its value is not in the token.
     *
     * @param string $name claim name, e.g. `groups`
     */
    public function hasDistributedClaim(string $name): bool;

    /**
     * Whether the preset's groups claim was sent as a distributed claim.
     *
     * E.g. Entra groups overage: {@see getGroups()} is then incomplete; consumers should fail closed.
     */
    public function hasDistributedGroups(): bool;
}
