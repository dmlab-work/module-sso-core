<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Test\Unit\Model\Mapping;

use DmLab\SsoCore\Model\Mapping\MappingEngine;
use PHPUnit\Framework\TestCase;

class MappingEngineTest extends TestCase
{
    /**
     * @var MappingEngine
     */
    private MappingEngine $engine;

    protected function setUp(): void
    {
        $this->engine = new MappingEngine();
    }

    public function testSingleMatch(): void
    {
        $result = $this->engine->resolve(
            ['admins'],
            ['admins' => 'administrators', 'staff' => 'general'],
            'default-role'
        );

        self::assertSame(['administrators'], $result);
    }

    public function testMultipleMatches(): void
    {
        $result = $this->engine->resolve(
            ['admins', 'staff'],
            ['admins' => 'administrators', 'staff' => 'general'],
            'default-role'
        );

        self::assertSame(['administrators', 'general'], $result);
    }

    public function testNoMatchReturnsDefault(): void
    {
        $result = $this->engine->resolve(
            ['guests'],
            ['admins' => 'administrators'],
            'default-role'
        );

        self::assertSame(['default-role'], $result);
    }

    public function testNoMatchWithoutDefaultReturnsEmpty(): void
    {
        $result = $this->engine->resolve(
            ['guests'],
            ['admins' => 'administrators']
        );

        self::assertSame([], $result);
    }

    public function testEmptySourceValuesReturnsDefault(): void
    {
        $result = $this->engine->resolve(
            [],
            ['admins' => 'administrators'],
            'default-role'
        );

        self::assertSame(['default-role'], $result);
    }

    public function testDuplicateTargetsAreDeduplicatedPreservingOrder(): void
    {
        $result = $this->engine->resolve(
            ['admins', 'superusers', 'staff'],
            ['admins' => 'administrators', 'superusers' => 'administrators', 'staff' => 'general'],
            'default-role'
        );

        self::assertSame(['administrators', 'general'], $result);
    }

    public function testMatchTakesPrecedenceOverDefault(): void
    {
        $result = $this->engine->resolve(
            ['admins', 'guests'],
            ['admins' => 'administrators'],
            'default-role'
        );

        self::assertSame(['administrators'], $result);
    }

    public function testMatchingIsCaseSensitive(): void
    {
        $result = $this->engine->resolve(
            ['Admins'],
            ['admins' => 'administrators'],
            'default-role'
        );

        self::assertSame(['default-role'], $result);
    }

    public function testNumericTargetsKeepStringType(): void
    {
        $result = $this->engine->resolve(
            ['admins', 'staff'],
            ['admins' => '5', 'staff' => '3'],
            '1'
        );

        self::assertSame(['5', '3'], $result);
    }

    public function testRuleOrderWinsOverIdpGroupOrder(): void
    {
        $result = $this->engine->resolve(
            ['staff', 'admins'],
            ['admins' => 'administrators', 'staff' => 'general'],
            'default-role'
        );

        self::assertSame(['administrators', 'general'], $result);
    }

    public function testNumericSourceKeysMatch(): void
    {
        $result = $this->engine->resolve(
            ['7', '123'],
            ['123' => '5', '7' => '3'],
            '1'
        );

        self::assertSame(['5', '3'], $result);
    }
}
