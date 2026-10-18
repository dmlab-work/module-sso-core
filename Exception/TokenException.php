<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Exception;

/**
 * Thrown when the token endpoint request fails or returns an unusable response.
 */
class TokenException extends \RuntimeException
{
}
