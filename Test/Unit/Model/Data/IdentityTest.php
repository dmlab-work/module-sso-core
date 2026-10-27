<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Test\Unit\Model\Data;

use DmLab\SsoCore\Api\Data\IdentityInterface;
use DmLab\SsoCore\Model\Data\Identity;
use PHPUnit\Framework\TestCase;

class IdentityTest extends TestCase
{
    public function testImplementsContract(): void
    {
        self::assertInstanceOf(IdentityInterface::class, new Identity('sub-1'));
    }

    public function testExposesAllValues(): void
    {
        $identity = new Identity('sub-1', 'user@example.com', 'Jane Doe', ['admins', 'staff']);

        self::assertSame('sub-1', $identity->getSubjectId());
        self::assertSame('user@example.com', $identity->getEmail());
        self::assertSame('Jane Doe', $identity->getName());
        self::assertSame(['admins', 'staff'], $identity->getGroups());
    }

    public function testExposesIssuer(): void
    {
        $identity = new Identity('sub-1', null, null, [], false, 'https://dev.okta.com');

        self::assertSame('https://dev.okta.com', $identity->getIssuer());
    }

    public function testIssuerDefaultsToEmpty(): void
    {
        self::assertSame('', (new Identity('sub-1'))->getIssuer());
    }

    public function testEmailAndNameDefaultToNull(): void
    {
        $identity = new Identity('sub-1');

        self::assertNull($identity->getEmail());
        self::assertNull($identity->getName());
    }

    public function testGroupsDefaultToEmptyArray(): void
    {
        self::assertSame([], (new Identity('sub-1'))->getGroups());
    }

    public function testGroupsAreReindexedAndStringified(): void
    {
        $identity = new Identity('sub-1', null, null, [5 => 'a', 9 => 42]);

        self::assertSame(['a', '42'], $identity->getGroups());
    }

    public function testEmailVerifiedDefaultsToFalse(): void
    {
        self::assertFalse((new Identity('sub-1', 'user@example.com'))->isEmailVerified());
    }

    public function testEmailVerifiedTrueWithEmail(): void
    {
        self::assertTrue((new Identity('sub-1', 'user@example.com', null, [], true))->isEmailVerified());
    }

    public function testEmailVerifiedForcedFalseWithoutEmail(): void
    {
        self::assertFalse((new Identity('sub-1', null, null, [], true))->isEmailVerified());
    }

    public function testEmailVerifiedForcedFalseWithEmptyEmail(): void
    {
        self::assertFalse((new Identity('sub-1', '', null, [], true))->isEmailVerified());
    }
}
