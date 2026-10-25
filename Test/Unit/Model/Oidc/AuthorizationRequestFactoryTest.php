<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Test\Unit\Model\Oidc;

use DmLab\SsoCore\Model\Oidc\AuthorizationRequest;
use DmLab\SsoCore\Model\Oidc\AuthorizationRequestFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class AuthorizationRequestFactoryTest extends TestCase
{
    private const ENDPOINT = 'https://dev.okta.com/oauth2/v1/authorize';
    private const CLIENT_ID = 'client-123';
    private const REDIRECT = 'https://magento.loc/sso/callback';

    private function build(): AuthorizationRequest
    {
        $factory = new AuthorizationRequestFactory();

        return $factory->create(
            self::ENDPOINT,
            self::CLIENT_ID,
            self::REDIRECT,
            ['openid', 'profile', 'email']
        );
    }

    /**
     * @return array<string, string>
     */
    private function queryParams(string $url): array
    {
        $query = parse_url($url, PHP_URL_QUERY);
        parse_str((string)$query, $params);

        /** @var array<string, string> $params */
        return $params;
    }

    public function testUrlKeepsEndpointAndCarriesRequiredParams(): void
    {
        $request = $this->build();

        self::assertStringStartsWith(self::ENDPOINT . '?', $request->getUrl());

        $params = $this->queryParams($request->getUrl());

        self::assertSame('code', $params['response_type']);
        self::assertSame(self::CLIENT_ID, $params['client_id']);
        self::assertSame(self::REDIRECT, $params['redirect_uri']);
        self::assertSame('openid profile email', $params['scope']);
        self::assertArrayHasKey('state', $params);
        self::assertArrayHasKey('nonce', $params);
    }

    public function testUsesPkceS256ChallengeDerivedFromVerifier(): void
    {
        $request = $this->build();
        $params = $this->queryParams($request->getUrl());

        self::assertSame('S256', $params['code_challenge_method']);

        $expectedChallenge = rtrim(
            strtr(base64_encode(hash('sha256', $request->getCodeVerifier(), true)), '+/', '-_'),
            '='
        );
        self::assertSame($expectedChallenge, $params['code_challenge']);
    }

    public function testVerifierIsUrlSafeAndWithinPkceLength(): void
    {
        $verifier = $this->build()->getCodeVerifier();

        self::assertGreaterThanOrEqual(43, strlen($verifier));
        self::assertLessThanOrEqual(128, strlen($verifier));
        self::assertMatchesRegularExpression('/^[A-Za-z0-9\-_]+$/', $verifier);
    }

    /** Each token is 32 random bytes base64url-encoded exactly once (43 chars), not a re-encoded base64 string. */
    public function testTokensEncodeThirtyTwoRawBytesOnce(): void
    {
        $request = $this->build();

        foreach ([$request->getState(), $request->getNonce(), $request->getCodeVerifier()] as $token) {
            self::assertSame(43, strlen($token));
            $raw = base64_decode(strtr($token, '-_', '+/'), true);
            self::assertIsString($raw);
            self::assertSame(32, strlen($raw));
        }
    }

    public function testStateNonceAndVerifierAreDistinctAndRandom(): void
    {
        $first = $this->build();
        $second = $this->build();

        // Distinct within one request.
        self::assertNotSame($first->getState(), $first->getNonce());
        self::assertNotSame($first->getState(), $first->getCodeVerifier());
        self::assertNotSame($first->getNonce(), $first->getCodeVerifier());

        // Distinct across requests (random per call).
        self::assertNotSame($first->getState(), $second->getState());
        self::assertNotSame($first->getNonce(), $second->getNonce());
        self::assertNotSame($first->getCodeVerifier(), $second->getCodeVerifier());
    }

    public function testReturnedStateMatchesUrlParams(): void
    {
        $request = $this->build();
        $params = $this->queryParams($request->getUrl());

        self::assertSame($request->getState(), $params['state']);
        self::assertSame($request->getNonce(), $params['nonce']);
    }

    public function testAppendsToEndpointThatAlreadyHasQuery(): void
    {
        $factory = new AuthorizationRequestFactory();
        $request = $factory->create(
            self::ENDPOINT . '?foo=bar',
            self::CLIENT_ID,
            self::REDIRECT,
            ['openid']
        );

        $params = $this->queryParams($request->getUrl());

        self::assertStringContainsString('?foo=bar&', $request->getUrl());
        self::assertSame('bar', $params['foo']);
        self::assertSame('openid', $params['scope']);
    }

    public function testExtraParamsAppearRfc3986EncodedAfterCoreParams(): void
    {
        $factory = new AuthorizationRequestFactory();
        $request = $factory->create(
            self::ENDPOINT,
            self::CLIENT_ID,
            self::REDIRECT,
            ['openid'],
            ['hd' => 'example.com', 'login_hint' => 'jane doe+x@example.com']
        );

        $url = $request->getUrl();
        $params = $this->queryParams($url);

        self::assertSame('example.com', $params['hd']);
        self::assertSame('jane doe+x@example.com', $params['login_hint']);
        self::assertStringContainsString('login_hint=jane%20doe%2Bx%40example.com', $url);
        self::assertGreaterThan(strpos($url, 'code_challenge_method='), strpos($url, 'hd='));
    }

    public function testEmptyExtraParamsLeaveUrlUnchanged(): void
    {
        $factory = new AuthorizationRequestFactory();

        $without = $factory->create(self::ENDPOINT, self::CLIENT_ID, self::REDIRECT, ['openid']);
        $with = $factory->create(self::ENDPOINT, self::CLIENT_ID, self::REDIRECT, ['openid'], []);

        // Tokens are random per call; compare everything else.
        $random = ['state' => '', 'nonce' => '', 'code_challenge' => ''];
        self::assertSame(
            array_merge($this->queryParams($without->getUrl()), $random),
            array_merge($this->queryParams($with->getUrl()), $random)
        );
    }

    public function testExtraParamsAppendToEndpointWithQuery(): void
    {
        $factory = new AuthorizationRequestFactory();
        $request = $factory->create(
            self::ENDPOINT . '?foo=bar',
            self::CLIENT_ID,
            self::REDIRECT,
            ['openid'],
            ['domain_hint' => 'contoso.com']
        );

        $params = $this->queryParams($request->getUrl());

        self::assertStringContainsString('?foo=bar&', $request->getUrl());
        self::assertSame('bar', $params['foo']);
        self::assertSame('contoso.com', $params['domain_hint']);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function reservedParamProvider(): array
    {
        return [
            'response_type' => ['response_type'],
            'client_id' => ['client_id'],
            'redirect_uri' => ['redirect_uri'],
            'scope' => ['scope'],
            'state' => ['state'],
            'nonce' => ['nonce'],
            'code_challenge' => ['code_challenge'],
            'code_challenge_method' => ['code_challenge_method'],
        ];
    }

    #[DataProvider('reservedParamProvider')]
    public function testReservedExtraParamRejected(string $key): void
    {
        $factory = new AuthorizationRequestFactory();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($key);

        $factory->create(self::ENDPOINT, self::CLIENT_ID, self::REDIRECT, ['openid'], [$key => 'x']);
    }

    /**
     * @return array<string, array{mixed}>
     */
    public static function nonStringValueProvider(): array
    {
        return [
            'int' => [1],
            'bool' => [true],
            'null' => [null],
            'array' => [['a']],
        ];
    }

    #[DataProvider('nonStringValueProvider')]
    public function testNonStringExtraParamValueRejected(mixed $value): void
    {
        $factory = new AuthorizationRequestFactory();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('hd');

        $factory->create(self::ENDPOINT, self::CLIENT_ID, self::REDIRECT, ['openid'], ['hd' => $value]);
    }
}
