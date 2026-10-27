<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Model\Oidc;

use DmLab\SsoCore\Api\Data\IdentityInterface;
use DmLab\SsoCore\Api\EmailVerificationResolverInterface;
use DmLab\SsoCore\Api\ProviderPresetInterface;
use DmLab\SsoCore\Model\Data\Identity;

/**
 * Normalizes a validated OIDC claim set into a provider-agnostic {@see Identity}.
 *
 * `sub` and `iss` are required; `email` and `name` are optional; groups are read from the
 * preset's configured groups claim and coerced to a `string[]`. Email verification
 * comes from the preset's {@see EmailVerificationResolverInterface}, else `email_verified`.
 */
class IdentityFactory
{
    /**
     * Normalize a validated claim set into an Identity.
     *
     * @param array<string,mixed> $claims validated ID-token claims
     * @param ProviderPresetInterface $preset
     * @throws \InvalidArgumentException when the mandatory `sub` or `iss` claim is absent
     */
    public function create(array $claims, ProviderPresetInterface $preset): IdentityInterface
    {
        $subjectId = $this->stringOrNull($claims['sub'] ?? null);
        if ($subjectId === null || $subjectId === '') {
            throw new \InvalidArgumentException('Claim set is missing a usable "sub" claim.');
        }
        $issuer = $this->stringOrNull($claims['iss'] ?? null);
        if ($issuer === null || $issuer === '') {
            throw new \InvalidArgumentException('Claim set is missing a usable "iss" claim.');
        }

        return new Identity(
            $subjectId,
            $this->stringOrNull($claims['email'] ?? null),
            $this->stringOrNull($claims['name'] ?? null),
            $this->extractGroups($claims, $preset->getGroupsClaim()),
            $this->resolveEmailVerified($claims, $preset),
            $issuer
        );
    }

    /**
     * Resolve email verification: preset resolver first, else strict `email_verified` true / "true".
     *
     * @param array<string,mixed> $claims
     * @param ProviderPresetInterface $preset
     */
    private function resolveEmailVerified(array $claims, ProviderPresetInterface $preset): bool
    {
        if ($preset instanceof EmailVerificationResolverInterface) {
            $resolved = $preset->resolveEmailVerified($claims);
            if ($resolved !== null) {
                return $resolved;
            }
        }

        $value = $claims['email_verified'] ?? null;

        return $value === true || (is_string($value) && strtolower($value) === 'true');
    }

    /**
     * Extract group memberships from the configured groups claim.
     *
     * @param array<string,mixed> $claims
     * @param string|null $groupsClaim
     * @return string[]
     */
    private function extractGroups(array $claims, ?string $groupsClaim): array
    {
        if ($groupsClaim === null || !array_key_exists($groupsClaim, $claims)) {
            return [];
        }

        $value = $claims[$groupsClaim];
        if ($value === null) {
            return [];
        }

        $groups = is_array($value) ? array_values($value) : [$value];

        // Coerce scalar members to strings; skip nested arrays/objects so a malformed
        // groups claim yields no spurious "Array" entries (and no PHP warning).
        return array_values(array_map(
            static fn($group) => (string)$group,
            array_filter($groups, static fn($group) => is_scalar($group))
        ));
    }

    /**
     * Coerce a scalar claim value to a string, or null for arrays/null.
     *
     * @param mixed $value
     */
    private function stringOrNull(mixed $value): ?string
    {
        if ($value === null || is_array($value)) {
            return null;
        }

        return (string)$value;
    }
}
