<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Exception;

/**
 * Thrown when the OIDC discovery document cannot be fetched or is malformed.
 */
class DiscoveryException extends \RuntimeException
{
}
