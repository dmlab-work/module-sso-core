<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Test\Unit;

use DmLab\SsoCore\Api\ProviderPresetInterface;
use DmLab\SsoCore\Model\Mapping\MappingEngine;
use DmLab\SsoCore\Model\Oidc\AuthorizationRequestFactory;
use DmLab\SsoCore\Model\Oidc\IdentityFactory;
use DmLab\SsoCore\Model\Oidc\IdTokenValidator;
use DmLab\SsoCore\Model\Oidc\JwksClient;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Magento\Framework\Cache\FrontendInterface;
use Magento\Framework\HTTP\ClientFactory;
use Magento\Framework\HTTP\ClientInterface;
use Magento\Framework\Math\Random;
use Magento\Framework\Serialize\Serializer\Json;
use PHPUnit\Framework\TestCase;

/**
 * Task 9 acceptance check: a product-module consumer stub drives the whole engine
 * end-to-end using only the public surface — build an auth URL from a preset,
 * validate a real ID token, normalize an Identity, and map its groups to target
 * keys. Proves the pieces compose, not just that each unit works in isolation.
 */
class AcceptanceFlowTest extends TestCase
{
    private const ISSUER = 'https://dev.okta.com';
    private const AUDIENCE = 'client-abc';
    private const REDIRECT_URI = 'https://magento.loc/sso/callback';
    private const AUTH_ENDPOINT = 'https://dev.okta.com/oauth2/v1/authorize';
    private const JWKS_URI = 'https://dev.okta.com/oauth2/v1/keys';
    private const NOW = 1_700_000_000;

    /**
     * @var JWK
     */
    private JWK $privateKey;

    /**
     * @var JWKSet
     */
    private JWKSet $keySet;

    protected function setUp(): void
    {
        $this->privateKey = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig', 'kid' => 'k1']);
        $this->keySet = new JWKSet([$this->privateKey->toPublic()]);
    }

    public function testConsumerStubCompletesFullOidcFlow(): void
    {
        $preset = $this->preset();

        // 1. Build the authorization request from the preset's scopes + PKCE.
        $authRequest = (new AuthorizationRequestFactory(new Random()))->create(
            self::AUTH_ENDPOINT,
            self::AUDIENCE,
            self::REDIRECT_URI,
            $preset->getDefaultScopes()
        );

        parse_str((string)parse_url($authRequest->getUrl(), PHP_URL_QUERY), $params);
        self::assertSame('code', $params['response_type']);
        self::assertSame(self::AUDIENCE, $params['client_id']);
        self::assertSame('openid profile email groups', $params['scope']);
        self::assertSame('S256', $params['code_challenge_method']);
        self::assertSame($authRequest->getState(), $params['state']);
        self::assertSame($authRequest->getNonce(), $params['nonce']);

        // 2. IdP redirects back; validate the ID token it issued against the JWKS.
        $idToken = $this->mintIdToken([
            'iss' => self::ISSUER,
            'aud' => self::AUDIENCE,
            'sub' => 'okta-user-42',
            'email' => 'jane@example.com',
            'name' => 'Jane Doe',
            'nonce' => $authRequest->getNonce(),
            'groups' => ['Admins', 'Everyone'],
            'iat' => self::NOW,
            'exp' => self::NOW + 300,
        ]);

        $claims = (new IdTokenValidator(new Json()))->validate(
            $idToken,
            $this->keySet,
            self::ISSUER,
            self::AUDIENCE,
            $authRequest->getNonce(),
            self::NOW
        );

        // 3. Normalize the validated claims into a provider-agnostic Identity.
        $identity = (new IdentityFactory())->create($claims, $preset);
        self::assertSame('okta-user-42', $identity->getSubjectId());
        self::assertSame('jane@example.com', $identity->getEmail());
        self::assertSame('Jane Doe', $identity->getName());
        self::assertSame(['Admins', 'Everyone'], $identity->getGroups());

        // 4. Map the IdP groups to target keys (e.g. Magento role ids).
        $roles = (new MappingEngine())->resolve(
            $identity->getGroups(),
            ['Admins' => 'administrators', 'Support' => 'support-agents'],
            'general'
        );
        self::assertSame(['administrators'], $roles);
    }

    public function testConsumerStubFallsBackToDefaultRoleWhenNoGroupMatches(): void
    {
        $preset = $this->preset();

        $idToken = $this->mintIdToken([
            'iss' => self::ISSUER,
            'aud' => self::AUDIENCE,
            'sub' => 'okta-user-99',
            'nonce' => 'nonce-1',
            'groups' => ['Contractors'],
            'iat' => self::NOW,
            'exp' => self::NOW + 300,
        ]);

        $claims = (new IdTokenValidator(new Json()))->validate(
            $idToken,
            $this->keySet,
            self::ISSUER,
            self::AUDIENCE,
            'nonce-1',
            self::NOW
        );

        $identity = (new IdentityFactory())->create($claims, $preset);
        self::assertNull($identity->getEmail());

        $roles = (new MappingEngine())->resolve(
            $identity->getGroups(),
            ['Admins' => 'administrators'],
            'general'
        );
        self::assertSame(['general'], $roles);
    }

    public function testKeyRotationValidatesAfterJwksRefetch(): void
    {
        $rotatedKey = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig', 'kid' => 'k2']);

        // Cache still holds the pre-rotation set (k1 only); the IdP now serves k2.
        $store = ['dmlab_ssocore_oidc_jwks_' . hash('sha256', self::JWKS_URI) => (string)json_encode($this->keySet)];
        $cache = $this->createStub(FrontendInterface::class);
        $cache->method('load')->willReturnCallback(static fn(string $id) => $store[$id] ?? false);
        $cache->method('save')->willReturnCallback(static function ($data, $id) use (&$store): bool {
            $store[$id] = $data;

            return true;
        });

        $http = $this->createStub(ClientInterface::class);
        $http->method('getStatus')->willReturn(200);
        $http->method('getBody')->willReturn((string)json_encode(new JWKSet([$rotatedKey->toPublic()])));
        $factory = $this->createStub(ClientFactory::class);
        $factory->method('create')->willReturn($http);

        $idToken = $this->mintIdToken([
            'iss' => self::ISSUER,
            'aud' => self::AUDIENCE,
            'sub' => 'okta-user-7',
            'nonce' => 'nonce-r',
            'iat' => self::NOW,
            'exp' => self::NOW + 300,
        ], $rotatedKey, 'k2');

        $keySet = (new JwksClient($factory, $cache))->getKeySetForToken(self::JWKS_URI, $idToken);

        $claims = (new IdTokenValidator(new Json()))->validate(
            $idToken,
            $keySet,
            self::ISSUER,
            self::AUDIENCE,
            'nonce-r',
            self::NOW
        );
        self::assertSame('okta-user-7', $claims['sub']);
    }

    private function preset(): ProviderPresetInterface
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
                return rtrim((string)($config['domain'] ?? ''), '/') . '/.well-known/openid-configuration';
            }

            public function getDefaultScopes(): array
            {
                return ['openid', 'profile', 'email', 'groups'];
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

    /**
     * @param array<string, mixed> $claims
     * @param JWK|null $key defaults to the original signing key
     * @param string $kid
     */
    private function mintIdToken(array $claims, ?JWK $key = null, string $kid = 'k1'): string
    {
        $builder = new JWSBuilder(new AlgorithmManager([new RS256()]));
        $jws = $builder->create()
            ->withPayload((string)json_encode($claims), false)
            ->addSignature($key ?? $this->privateKey, ['alg' => 'RS256', 'kid' => $kid], [])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }
}
