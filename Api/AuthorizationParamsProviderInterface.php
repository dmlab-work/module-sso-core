<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Api;

/**
 * Optional preset capability: extra authorization request parameters.
 *
 * Implemented next to {@see ProviderPresetInterface} by presets that need IdP-specific
 * params on the authorization URL (e.g. Google `hd`, Entra `domain_hint`).
 */
interface AuthorizationParamsProviderInterface
{
    /**
     * Extra query params appended after the core authorization request params.
     *
     * @param array<string,mixed> $config provider configuration
     * @return array<string,string>
     */
    public function getAuthorizationParams(array $config): array;
}
