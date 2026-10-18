<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Test\Unit\Api;

use DmLab\SsoCore\Api\ProviderPresetInterface;
use PHPUnit\Framework\TestCase;

class ProviderPresetInterfaceTest extends TestCase
{
    private function fakePreset(): ProviderPresetInterface
    {
        return new class implements ProviderPresetInterface {
            public function getCode(): string
            {
                return 'okta';
            }

            public function getLabel(): string
            {
                return 'Okta';
            }

            public function buildDiscoveryUrl(array $config): string
            {
                $domain = rtrim((string)($config['domain'] ?? ''), '/');

                return $domain . '/.well-known/openid-configuration';
            }

            public function getDefaultScopes(): array
            {
                return ['openid', 'profile', 'email'];
            }

            public function getGroupsClaim(): ?string
            {
                return 'groups';
            }

            public function getButtonLabel(): string
            {
                return 'Sign in with Okta';
            }

            public function getButtonIconUrl(): ?string
            {
                return null;
            }
        };
    }

    public function testImplementsContract(): void
    {
        self::assertInstanceOf(ProviderPresetInterface::class, $this->fakePreset());
    }

    public function testExposesIdentityAndBranding(): void
    {
        $preset = $this->fakePreset();

        self::assertSame('okta', $preset->getCode());
        self::assertSame('Okta', $preset->getLabel());
        self::assertSame('Sign in with Okta', $preset->getButtonLabel());
        self::assertNull($preset->getButtonIconUrl());
    }

    public function testDefaultScopesIncludeOpenid(): void
    {
        self::assertContains('openid', $this->fakePreset()->getDefaultScopes());
    }

    public function testGroupsClaim(): void
    {
        self::assertSame('groups', $this->fakePreset()->getGroupsClaim());
    }

    public function testBuildDiscoveryUrlFromConfig(): void
    {
        $url = $this->fakePreset()->buildDiscoveryUrl(['domain' => 'https://dev.okta.com/']);

        self::assertSame('https://dev.okta.com/.well-known/openid-configuration', $url);
    }
}
