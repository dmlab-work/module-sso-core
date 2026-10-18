<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Api;

/**
 * Optional preset capability: opt out of the OIDC Discovery §4.3 issuer match.
 *
 * Implemented next to {@see ProviderPresetInterface} by presets whose issuer legitimately
 * differs from the discovery URL prefix (e.g. Entra verified-domain tenant).
 */
interface DiscoveryIssuerPolicyInterface
{
    /**
     * Whether the discovery document's issuer must equal the discovery URL prefix.
     *
     * @param array<string,mixed> $config provider configuration
     */
    public function requiresIssuerMatch(array $config): bool;
}
