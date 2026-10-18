<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Test\Unit\Model\Oidc;

use DmLab\SsoCore\Exception\TokenException;
use DmLab\SsoCore\Model\Oidc\TokenClient;
use DmLab\SsoCore\Model\Oidc\TokenResponse;
use Magento\Framework\HTTP\ClientFactory;
use Magento\Framework\HTTP\ClientInterface;
use Magento\Framework\Serialize\Serializer\Json;
use PHPUnit\Framework\TestCase;

class TokenClientTest extends TestCase
{
    private const ENDPOINT = 'https://dev.okta.com/oauth2/v1/token';
    private const REDIRECT = 'https://magento.loc/sso/callback';
    private const CLIENT_ID = 'client-abc';
    private const CODE = 'auth-code-123';
    private const VERIFIER = 'pkce-verifier-456';

    private function client(ClientInterface $http): TokenClient
    {
        return new TokenClient($this->factory($http), new Json());
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function body(array $overrides = []): string
    {
        return (string)json_encode(array_merge([
            'id_token' => 'header.payload.signature',
            'access_token' => 'at-789',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'scope' => 'openid profile',
        ], $overrides));
    }

    private function exchange(TokenClient $client, ?string $secret = null): TokenResponse
    {
        return $client->exchangeCode(
            self::ENDPOINT,
            self::CODE,
            self::REDIRECT,
            self::CLIENT_ID,
            self::VERIFIER,
            $secret
        );
    }

    public function testExchangesCodeAndParsesResponse(): void
    {
        $http = $this->createMock(ClientInterface::class);
        $http->expects(self::once())
            ->method('post')
            ->with(self::ENDPOINT, self::callback(function (array $params): bool {
                return $params['grant_type'] === 'authorization_code'
                    && $params['code'] === self::CODE
                    && $params['redirect_uri'] === self::REDIRECT
                    && $params['client_id'] === self::CLIENT_ID
                    && $params['code_verifier'] === self::VERIFIER
                    && !array_key_exists('client_secret', $params);
            }));
        $http->method('getStatus')->willReturn(200);
        $http->method('getBody')->willReturn($this->body());

        $response = $this->exchange($this->client($http));

        self::assertSame('header.payload.signature', $response->getIdToken());
        self::assertSame('at-789', $response->getAccessToken());
        self::assertSame('Bearer', $response->getTokenType());
        self::assertSame(3600, $response->getExpiresIn());
        self::assertSame('openid profile', $response->getScope());
        self::assertNull($response->getRefreshToken());
    }

    public function testIncludesClientSecretWhenProvided(): void
    {
        $http = $this->createMock(ClientInterface::class);
        $http->expects(self::once())
            ->method('post')
            ->with(self::ENDPOINT, self::callback(
                static fn(array $params): bool => ($params['client_secret'] ?? null) === 'shh'
            ));
        $http->method('getStatus')->willReturn(200);
        $http->method('getBody')->willReturn($this->body());

        $this->exchange($this->client($http), 'shh');
    }

    public function testThrowsWhenIdTokenMissing(): void
    {
        $http = $this->httpReturning(200, $this->body(['id_token' => '']));

        $this->expectException(TokenException::class);
        $this->expectExceptionMessage('id_token');

        $this->exchange($this->client($http));
    }

    public function testThrowsOnErrorStatusWithDescription(): void
    {
        $http = $this->httpReturning(400, (string)json_encode([
            'error' => 'invalid_grant',
            'error_description' => 'code already used',
        ]));

        $this->expectException(TokenException::class);
        $this->expectExceptionMessage('invalid_grant');

        $this->exchange($this->client($http));
    }

    public function testThrowsOnInvalidJson(): void
    {
        $http = $this->httpReturning(200, '<html>error</html>');

        $this->expectException(TokenException::class);
        $this->expectExceptionMessage('valid JSON');

        $this->exchange($this->client($http));
    }

    public function testThrowsWhenHttpClientFails(): void
    {
        $http = $this->createStub(ClientInterface::class);
        $http->method('post')->willThrowException(new \RuntimeException('connection refused'));

        $this->expectException(TokenException::class);
        $this->expectExceptionMessage('connection refused');

        $this->exchange($this->client($http));
    }

    private function httpReturning(int $status, string $body): ClientInterface
    {
        $http = $this->createStub(ClientInterface::class);
        $http->method('getStatus')->willReturn($status);
        $http->method('getBody')->willReturn($body);

        return $http;
    }

    public function testCreatesBoundedHttpsClientPerRequestWithAcceptHeader(): void
    {
        $first = $this->recordingHttp($log1, $this->body());
        $second = $this->recordingHttp($log2, $this->body());

        $factory = $this->createMock(ClientFactory::class);
        $factory->expects(self::exactly(2))->method('create')->willReturnOnConsecutiveCalls($first, $second);

        $client = new TokenClient($factory, new Json());
        $this->exchange($client);
        $this->exchange($client);

        $this->assertBounded($log1);
        $this->assertBounded($log2);
        self::assertSame(['Accept' => 'application/json'], $log1['headers']);
        self::assertSame(['Accept' => 'application/json'], $log2['headers']);
    }

    public function testAppliesConfiguredTimeouts(): void
    {
        $http = $this->recordingHttp($log, $this->body());

        $this->exchange(new TokenClient($this->factory($http), new Json(), 2, 7));

        $this->assertBounded($log, 2, 7);
    }

    /**
     * Client mock that records timeout/options/headers and answers one request.
     *
     * @param array<string, mixed>|null $log
     */
    private function recordingHttp(?array &$log, string $body, int $status = 200): ClientInterface
    {
        $log = ['timeout' => null, 'options' => [], 'headers' => []];
        $http = $this->createStub(ClientInterface::class);
        $http->method('setTimeout')->willReturnCallback(function ($value) use (&$log): void {
            $log['timeout'] = $value;
        });
        $http->method('setOption')->willReturnCallback(function ($key, $value) use (&$log): void {
            $log['options'][$key] = $value;
        });
        $http->method('addHeader')->willReturnCallback(function ($name, $value) use (&$log): void {
            $log['headers'][$name] = $value;
        });
        $http->method('getStatus')->willReturn($status);
        $http->method('getBody')->willReturn($body);

        return $http;
    }

    /**
     * @param array<string, mixed> $log
     */
    private function assertBounded(array $log, int $connectTimeout = 5, int $timeout = 10): void
    {
        self::assertSame($timeout, $log['timeout']);
        self::assertSame($connectTimeout, $log['options'][CURLOPT_CONNECTTIMEOUT] ?? null);
        self::assertSame(CURLPROTO_HTTPS, $log['options'][CURLOPT_PROTOCOLS] ?? null);
    }

    private function factory(ClientInterface $http): ClientFactory
    {
        $factory = $this->createStub(ClientFactory::class);
        $factory->method('create')->willReturn($http);

        return $factory;
    }
}
