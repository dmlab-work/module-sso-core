<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Test\Unit\Api;

use DmLab\SsoCore\Api\AuthorizationStateStorageInterface;
use DmLab\SsoCore\Api\Data\AuthorizationStateInterface;
use DmLab\SsoCore\Model\Oidc\AuthorizationRequest;
use PHPUnit\Framework\TestCase;

class AuthorizationStateStorageInterfaceTest extends TestCase
{
    private function inMemoryStorage(): AuthorizationStateStorageInterface
    {
        return new class implements AuthorizationStateStorageInterface {
            /** @var array<string, AuthorizationStateInterface> */
            private array $store = [];

            public function save(AuthorizationStateInterface $state): void
            {
                $this->store[$state->getState()] = $state;
            }

            public function consume(string $state): ?AuthorizationStateInterface
            {
                $found = $this->store[$state] ?? null;
                unset($this->store[$state]);

                return $found;
            }
        };
    }

    public function testRoundTripsSavedState(): void
    {
        $storage = $this->inMemoryStorage();
        $request = new AuthorizationRequest('https://idp/authorize', 'st', 'no', 'ver', 'https://idp');

        $storage->save($request);
        $loaded = $storage->consume('st');

        self::assertInstanceOf(AuthorizationStateInterface::class, $loaded);
        self::assertSame('st', $loaded->getState());
        self::assertSame('no', $loaded->getNonce());
        self::assertSame('ver', $loaded->getCodeVerifier());
        self::assertSame('https://idp', $loaded->getIssuer());
    }

    public function testConsumeIsSingleUse(): void
    {
        $storage = $this->inMemoryStorage();
        $storage->save(new AuthorizationRequest('https://idp/authorize', 'st', 'no', 'ver'));

        self::assertNotNull($storage->consume('st'));
        self::assertNull($storage->consume('st'));
    }

    public function testConsumeUnknownStateReturnsNull(): void
    {
        self::assertNull($this->inMemoryStorage()->consume('missing'));
    }
}
