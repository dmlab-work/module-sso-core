<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Model\Cache;

use Magento\Framework\App\Cache\Type\FrontendPool;
use Magento\Framework\Cache\Frontend\Decorator\TagScope;

/**
 * Dedicated, flushable cache type for OIDC discovery and JWKS documents.
 *
 * Gives `FrontendInterface` a resolvable instance (the framework ships no
 * preference for it) and lets admins flush IdP metadata — e.g. after a signing
 * key rotation — from Cache Management.
 */
class Type extends TagScope
{
    public const TYPE_IDENTIFIER = 'dmlab_ssocore';

    public const CACHE_TAG = 'DMLAB_SSOCORE';

    /**
     * @param FrontendPool $cacheFrontendPool
     */
    public function __construct(FrontendPool $cacheFrontendPool)
    {
        parent::__construct($cacheFrontendPool->get(self::TYPE_IDENTIFIER), self::CACHE_TAG);
    }
}
