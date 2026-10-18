<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Api;

/**
 * Optional preset capability: decide email verification from IdP-specific claims.
 *
 * Implemented next to {@see ProviderPresetInterface} by presets whose IdP does not
 * use the standard `email_verified` claim (e.g. Entra `xms_edov`).
 */
interface EmailVerificationResolverInterface
{
    /**
     * Resolve whether the email is verified; null falls back to the standard `email_verified` claim.
     *
     * @param array<string,mixed> $claims validated ID-token claims
     */
    public function resolveEmailVerified(array $claims): ?bool;
}
