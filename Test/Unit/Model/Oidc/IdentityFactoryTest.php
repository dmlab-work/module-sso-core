<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Test\Unit\Model\Oidc;

use DmLab\SsoCore\Api\EmailVerificationResolverInterface;
use DmLab\SsoCore\Api\ProviderPresetInterface;
use DmLab\SsoCore\Model\Oidc\IdentityFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class IdentityFactoryTest extends TestCase
{
    private const ISSUER = 'https://dev.okta.com';

    /**
     * @var IdentityFactory
     */
    private IdentityFactory $factory;

    protected function setUp(): void
    {
        $this->factory = new IdentityFactory();
    }

    private function preset(?string $groupsClaim = 'groups'): ProviderPresetInterface
    {
        return new class ($groupsClaim) implements ProviderPresetInterface {
            public function __construct(private readonly ?string $groupsClaim)
            {
            }

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
                return 'https://example.test/.well-known/openid-configuration';
            }

            public function getDefaultScopes(): array
            {
                return ['openid', 'profile', 'email'];
            }

            public function getGroupsClaim(): ?string
            {
                return $this->groupsClaim;
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

    public function testMapsAllClaims(): void
    {
        $identity = $this->factory->create(
            [
                'iss' => self::ISSUER,
                'sub' => 'okta|123',
                'email' => 'jane@example.com',
                'name' => 'Jane Doe',
                'groups' => ['admins', 'staff'],
            ],
            $this->preset()
        );

        self::assertSame('okta|123', $identity->getSubjectId());
        self::assertSame(self::ISSUER, $identity->getIssuer());
        self::assertSame('jane@example.com', $identity->getEmail());
        self::assertSame('Jane Doe', $identity->getName());
        self::assertSame(['admins', 'staff'], $identity->getGroups());
    }

    public function testEmailNameAndGroupsDefaultWhenAbsent(): void
    {
        $identity = $this->factory->create(['iss' => self::ISSUER, 'sub' => 'okta|123'], $this->preset());

        self::assertSame('okta|123', $identity->getSubjectId());
        self::assertNull($identity->getEmail());
        self::assertNull($identity->getName());
        self::assertSame([], $identity->getGroups());
    }

    public function testMissingSubjectIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->factory->create(['iss' => self::ISSUER, 'email' => 'jane@example.com'], $this->preset());
    }

    public function testEmptySubjectIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->factory->create(['iss' => self::ISSUER, 'sub' => ''], $this->preset());
    }

    public function testMissingIssuerIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('"iss"');

        $this->factory->create(['sub' => 'okta|123'], $this->preset());
    }

    public function testEmptyIssuerIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->factory->create(['iss' => '', 'sub' => 'okta|123'], $this->preset());
    }

    public function testEntraGroupsOverageIsFlaggedAsDistributed(): void
    {
        $identity = $this->factory->create(
            [
                'iss' => self::ISSUER,
                'sub' => 's',
                '_claim_names' => ['groups' => 'src1'],
                '_claim_sources' => ['src1' => ['endpoint' => 'https://graph.microsoft.com/v1.0/users/x']],
            ],
            $this->preset()
        );

        self::assertSame([], $identity->getGroups());
        self::assertTrue($identity->hasDistributedGroups());
        self::assertTrue($identity->hasDistributedClaim('groups'));
        self::assertFalse($identity->hasDistributedClaim('email'));
    }

    public function testDistributedClaimOtherThanGroupsDoesNotFlagGroups(): void
    {
        $identity = $this->factory->create(
            ['iss' => self::ISSUER, 'sub' => 's', 'groups' => ['a'], '_claim_names' => ['roles' => 'src1']],
            $this->preset()
        );

        self::assertFalse($identity->hasDistributedGroups());
        self::assertTrue($identity->hasDistributedClaim('roles'));
        self::assertSame(['a'], $identity->getGroups());
    }

    public function testNoGroupsClaimNeverFlagsDistributedGroups(): void
    {
        $identity = $this->factory->create(
            ['iss' => self::ISSUER, 'sub' => 's', '_claim_names' => ['groups' => 'src1']],
            $this->preset(null)
        );

        self::assertFalse($identity->hasDistributedGroups());
        self::assertTrue($identity->hasDistributedClaim('groups'));
    }

    public function testMalformedClaimNamesAreIgnored(): void
    {
        $identity = $this->factory->create(
            ['iss' => self::ISSUER, 'sub' => 's', '_claim_names' => 'groups'],
            $this->preset()
        );

        self::assertFalse($identity->hasDistributedGroups());
        self::assertFalse($identity->hasDistributedClaim('groups'));
    }

    public function testScalarGroupIsCoercedToStringArray(): void
    {
        $identity = $this->factory->create(
            ['iss' => self::ISSUER, 'sub' => 's', 'groups' => 'admins'],
            $this->preset()
        );

        self::assertSame(['admins'], $identity->getGroups());
    }

    public function testGroupValuesAreStringifiedAndReindexed(): void
    {
        $identity = $this->factory->create(
            ['iss' => self::ISSUER, 'sub' => 's', 'groups' => [3 => 42, 7 => 'staff']],
            $this->preset()
        );

        self::assertSame(['42', 'staff'], $identity->getGroups());
    }

    public function testNestedArrayGroupMembersAreSkipped(): void
    {
        $identity = $this->factory->create(
            ['iss' => self::ISSUER, 'sub' => 's', 'groups' => ['admins', ['nested'], 'staff']],
            $this->preset()
        );

        self::assertSame(['admins', 'staff'], $identity->getGroups());
    }

    public function testNullGroupsClaimYieldsEmptyGroups(): void
    {
        $identity = $this->factory->create(
            ['iss' => self::ISSUER, 'sub' => 's', 'groups' => ['admins']],
            $this->preset(null)
        );

        self::assertSame([], $identity->getGroups());
    }

    public function testGroupsClaimPointingToNullValueYieldsEmptyGroups(): void
    {
        $identity = $this->factory->create(
            ['iss' => self::ISSUER, 'sub' => 's', 'groups' => null],
            $this->preset()
        );

        self::assertSame([], $identity->getGroups());
    }

    public function testCustomGroupsClaimName(): void
    {
        $identity = $this->factory->create(
            ['iss' => self::ISSUER, 'sub' => 's', 'roles' => ['a', 'b'], 'groups' => ['ignored']],
            $this->preset('roles')
        );

        self::assertSame(['a', 'b'], $identity->getGroups());
    }

    /**
     * @return array<string,array{mixed,bool}>
     */
    public static function emailVerifiedClaimProvider(): array
    {
        return [
            'bool true' => [true, true],
            'string true' => ['true', true],
            'string TRUE' => ['TRUE', true],
            'bool false' => [false, false],
            'string false' => ['false', false],
            'int 1' => [1, false],
            'string 1' => ['1', false],
            'array' => [[true], false],
            'null' => [null, false],
        ];
    }

    #[DataProvider('emailVerifiedClaimProvider')]
    public function testEmailVerifiedClaimNormalization(mixed $claim, bool $expected): void
    {
        $identity = $this->factory->create(
            ['iss' => self::ISSUER, 'sub' => 's', 'email' => 'jane@example.com', 'email_verified' => $claim],
            $this->preset()
        );

        self::assertSame($expected, $identity->isEmailVerified());
    }

    public function testEmailVerifiedAbsentIsFalse(): void
    {
        $identity = $this->factory->create(
            ['iss' => self::ISSUER, 'sub' => 's', 'email' => 'jane@example.com'],
            $this->preset()
        );

        self::assertFalse($identity->isEmailVerified());
    }

    public function testEmailVerifiedWithoutEmailIsFalse(): void
    {
        $identity = $this->factory->create(
            ['iss' => self::ISSUER, 'sub' => 's', 'email_verified' => true],
            $this->preset()
        );

        self::assertFalse($identity->isEmailVerified());
    }

    public function testResolverTrueOverridesStandardClaim(): void
    {
        $identity = $this->factory->create(
            ['iss' => self::ISSUER, 'sub' => 's', 'email' => 'jane@example.com', 'email_verified' => false],
            $this->resolvingPreset(true)
        );

        self::assertTrue($identity->isEmailVerified());
    }

    public function testResolverFalseOverridesStandardClaim(): void
    {
        $identity = $this->factory->create(
            ['iss' => self::ISSUER, 'sub' => 's', 'email' => 'jane@example.com', 'email_verified' => true],
            $this->resolvingPreset(false)
        );

        self::assertFalse($identity->isEmailVerified());
    }

    public function testResolverNullFallsBackToStandardClaim(): void
    {
        $identity = $this->factory->create(
            ['iss' => self::ISSUER, 'sub' => 's', 'email' => 'jane@example.com', 'email_verified' => true],
            $this->resolvingPreset(null)
        );

        self::assertTrue($identity->isEmailVerified());
    }

    public function testResolverReceivesClaims(): void
    {
        $preset = $this->resolvingPreset(true);
        $claims = ['iss' => self::ISSUER, 'sub' => 's', 'email' => 'jane@example.com', 'xms_edov' => true];

        $this->factory->create($claims, $preset);

        self::assertSame($claims, $preset->receivedClaims);
    }

    public function testResolverTrueWithoutEmailIsFalse(): void
    {
        $identity = $this->factory->create(['iss' => self::ISSUER, 'sub' => 's'], $this->resolvingPreset(true));

        self::assertFalse($identity->isEmailVerified());
    }

    private function resolvingPreset(
        ?bool $resolved
    ): ProviderPresetInterface&EmailVerificationResolverInterface {
        return new class ($resolved) implements ProviderPresetInterface, EmailVerificationResolverInterface {
            /**
             * @var array<string,mixed>|null
             */
            public ?array $receivedClaims = null;

            public function __construct(private readonly ?bool $resolved)
            {
            }

            public function resolveEmailVerified(array $claims): ?bool
            {
                $this->receivedClaims = $claims;

                return $this->resolved;
            }

            public function getCode(): string
            {
                return 'azure';
            }

            public function getLabel(): string
            {
                return 'Azure';
            }

            public function buildDiscoveryUrl(array $config): string
            {
                return 'https://example.test/.well-known/openid-configuration';
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
                return 'Sign in with Azure';
            }

            public function getButtonIconUrl(): ?string
            {
                return null;
            }
        };
    }
}
