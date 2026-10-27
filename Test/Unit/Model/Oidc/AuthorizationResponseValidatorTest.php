<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Test\Unit\Model\Oidc;

use DmLab\SsoCore\Exception\AuthorizationResponseException;
use DmLab\SsoCore\Model\Oidc\AuthorizationRequest;
use DmLab\SsoCore\Model\Oidc\AuthorizationResponseValidator;
use DmLab\SsoCore\Model\Oidc\ProviderMetadata;
use PHPUnit\Framework\TestCase;

class AuthorizationResponseValidatorTest extends TestCase
{
    private const ISSUER = 'https://dev.okta.com';

    private function metadata(bool $issSupported = false): ProviderMetadata
    {
        return new ProviderMetadata(
            self::ISSUER,
            self::ISSUER . '/authorize',
            self::ISSUER . '/token',
            self::ISSUER . '/keys',
            [],
            [],
            $issSupported
        );
    }

    private function state(string $issuer = self::ISSUER): AuthorizationRequest
    {
        return new AuthorizationRequest('https://idp/authorize', 'st', 'no', 'ver', $issuer);
    }

    public function testMatchingIssParamPasses(): void
    {
        (new AuthorizationResponseValidator())->validateIssuer(self::ISSUER, $this->state(), $this->metadata(true));

        $this->addToAssertionCount(1);
    }

    public function testAbsentIssPassesWhenNotAdvertised(): void
    {
        (new AuthorizationResponseValidator())->validateIssuer(null, $this->state(), $this->metadata());

        $this->addToAssertionCount(1);
    }

    public function testAbsentIssRejectedWhenAdvertised(): void
    {
        $this->expectException(AuthorizationResponseException::class);
        $this->expectExceptionMessage('missing the "iss"');

        (new AuthorizationResponseValidator())->validateIssuer(null, $this->state(), $this->metadata(true));
    }

    public function testMismatchingIssRejectedEvenWhenNotAdvertised(): void
    {
        $this->expectException(AuthorizationResponseException::class);
        $this->expectExceptionMessage('does not match');

        (new AuthorizationResponseValidator())
            ->validateIssuer('https://evil.example', $this->state(), $this->metadata());
    }

    public function testIssComparisonIsExact(): void
    {
        $this->expectException(AuthorizationResponseException::class);

        (new AuthorizationResponseValidator())
            ->validateIssuer(self::ISSUER . '/', $this->state(), $this->metadata(true));
    }

    public function testStateIssuerOfAnotherProviderIsRejected(): void
    {
        $this->expectException(AuthorizationResponseException::class);
        $this->expectExceptionMessage('started with issuer');

        (new AuthorizationResponseValidator())
            ->validateIssuer(null, $this->state('https://other.example'), $this->metadata());
    }

    public function testStateWithoutIssuerFallsBackToDiscoveredIssuer(): void
    {
        (new AuthorizationResponseValidator())->validateIssuer(self::ISSUER, $this->state(''), $this->metadata(true));

        $this->addToAssertionCount(1);
    }
}
