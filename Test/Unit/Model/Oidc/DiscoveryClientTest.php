<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Test\Unit\Model\Oidc;

use DmLab\SsoCore\Exception\DiscoveryException;
use DmLab\SsoCore\Model\Oidc\DiscoveryClient;
use DmLab\SsoCore\Model\Oidc\ProviderMetadata;
use Magento\Framework\Cache\FrontendInterface;
use Magento\Framework\HTTP\ClientFactory;
use Magento\Framework\HTTP\ClientInterface;
use Magento\Framework\Serialize\Serializer\Json;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class DiscoveryClientTest extends TestCase
{
    private const URL = 'https://dev.okta.com/.well-known/openid-configuration';

    /**
     * @param array<string, mixed> $overrides
     */
    private function document(array $overrides = []): string
    {
        return (string)json_encode(array_merge([
            'issuer' => 'https://dev.okta.com',
            'authorization_endpoint' => 'https://dev.okta.com/oauth2/v1/authorize',
            'token_endpoint' => 'https://dev.okta.com/oauth2/v1/token',
            'jwks_uri' => 'https://dev.okta.com/oauth2/v1/keys',
        ], $overrides));
    }

    private function client(ClientInterface $http, FrontendInterface $cache): DiscoveryClient
    {
        return new DiscoveryClient($this->factory($http), $cache, new Json());
    }

    public function testFetchesParsesAndCachesOnMiss(): void
    {
        $body = $this->document();

        $cache = $this->createMock(FrontendInterface::class);
        $cache->method('load')->willReturn(false);
        $cache->expects(self::once())
            ->method('save')
            ->with($body, self::isString(), [], 3600);

        $http = $this->createMock(ClientInterface::class);
        $http->expects(self::once())->method('get')->with(self::URL);
        $http->method('getStatus')->willReturn(200);
        $http->method('getBody')->willReturn($body);

        $metadata = $this->client($http, $cache)->discover(self::URL);

        self::assertInstanceOf(ProviderMetadata::class, $metadata);
        self::assertSame('https://dev.okta.com', $metadata->getIssuer());
        self::assertSame('https://dev.okta.com/oauth2/v1/authorize', $metadata->getAuthorizationEndpoint());
        self::assertSame('https://dev.okta.com/oauth2/v1/token', $metadata->getTokenEndpoint());
        self::assertSame('https://dev.okta.com/oauth2/v1/keys', $metadata->getJwksUri());
        self::assertSame([], $metadata->getTokenEndpointAuthMethodsSupported());
    }

    public function testParsesTokenEndpointAuthMethods(): void
    {
        $http = $this->httpReturning($this->document([
            'token_endpoint_auth_methods_supported' => ['client_secret_post', 7, '', 'client_secret_basic'],
        ]));

        $metadata = $this->client($http, $this->coldCache())->discover(self::URL);

        self::assertSame(
            ['client_secret_post', 'client_secret_basic'],
            $metadata->getTokenEndpointAuthMethodsSupported()
        );
    }

    public function testIgnoresMalformedTokenEndpointAuthMethods(): void
    {
        $http = $this->httpReturning(
            $this->document(['token_endpoint_auth_methods_supported' => 'client_secret_post'])
        );

        $metadata = $this->client($http, $this->coldCache())->discover(self::URL);

        self::assertSame([], $metadata->getTokenEndpointAuthMethodsSupported());
    }

    public function testUsesCacheOnHitWithoutHttpCall(): void
    {
        $cache = $this->createMock(FrontendInterface::class);
        $cache->method('load')->willReturn($this->document());
        $cache->expects(self::never())->method('save');

        $http = $this->createMock(ClientInterface::class);
        $http->expects(self::never())->method('get');

        $metadata = $this->client($http, $cache)->discover(self::URL);

        self::assertSame('https://dev.okta.com', $metadata->getIssuer());
        self::assertSame('https://dev.okta.com/oauth2/v1/keys', $metadata->getJwksUri());
    }

    public function testThrowsOnMissingEndpoint(): void
    {
        $http = $this->httpReturning($this->document(['token_endpoint' => '']));

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('token_endpoint');

        $this->client($http, $this->coldCache())->discover(self::URL);
    }

    public function testThrowsOnNonHttpsDiscoveryUrl(): void
    {
        $http = $this->createMock(ClientInterface::class);
        $http->expects(self::never())->method('get');

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('must use HTTPS');

        $this->client($http, $this->coldCache())
            ->discover('http://dev.okta.com/.well-known/openid-configuration');
    }

    public function testThrowsOnNonHttpsEndpoint(): void
    {
        $http = $this->httpReturning($this->document([
            'token_endpoint' => 'http://dev.okta.com/oauth2/v1/token',
        ]));

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('token_endpoint must use HTTPS');

        $this->client($http, $this->coldCache())->discover(self::URL);
    }

    public function testThrowsOnInvalidJson(): void
    {
        $http = $this->httpReturning('<html>not json</html>');

        $this->expectException(DiscoveryException::class);

        $this->client($http, $this->coldCache())->discover(self::URL);
    }

    public function testThrowsOnNonJsonObject(): void
    {
        $http = $this->httpReturning('"a string"');

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('JSON object');

        $this->client($http, $this->coldCache())->discover(self::URL);
    }

    public function testThrowsOnHttpError(): void
    {
        $http = $this->createStub(ClientInterface::class);
        $http->method('getStatus')->willReturn(404);

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('HTTP 404');

        $this->client($http, $this->coldCache())->discover(self::URL);
    }

    public function testThrowsWhenHttpClientFails(): void
    {
        $http = $this->createStub(ClientInterface::class);
        $http->method('get')->willThrowException(new \RuntimeException('connection refused'));

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('connection refused');

        $this->client($http, $this->coldCache())->discover(self::URL);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function matchingIssuerProvider(): array
    {
        return [
            'okta org' => [
                'https://dev.okta.com/.well-known/openid-configuration',
                'https://dev.okta.com',
            ],
            'okta custom authorization server' => [
                'https://dev.okta.com/oauth2/default/.well-known/openid-configuration',
                'https://dev.okta.com/oauth2/default',
            ],
            'google root' => [
                'https://accounts.google.com/.well-known/openid-configuration',
                'https://accounts.google.com',
            ],
            'issuer with trailing slash (auth0)' => [
                'https://tenant.auth0.com/.well-known/openid-configuration',
                'https://tenant.auth0.com/',
            ],
        ];
    }

    #[DataProvider('matchingIssuerProvider')]
    public function testMatchingIssuerPasses(string $url, string $issuer): void
    {
        $http = $this->httpReturning($this->document(['issuer' => $issuer]));

        $metadata = $this->client($http, $this->coldCache())->discover($url);

        self::assertSame($issuer, $metadata->getIssuer());
    }

    public function testIssuerMismatchThrowsAndIsNotCached(): void
    {
        $cache = $this->createMock(FrontendInterface::class);
        $cache->method('load')->willReturn(false);
        $cache->expects(self::never())->method('save');

        $http = $this->httpReturning($this->document(['issuer' => 'https://evil.example.com']));

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('does not match expected "https://dev.okta.com"');

        $this->client($http, $cache)->discover(self::URL);
    }

    public function testIssuerWithExtraPathIsMismatch(): void
    {
        $http = $this->httpReturning($this->document(['issuer' => 'https://dev.okta.com/oauth2/default']));

        $this->expectException(DiscoveryException::class);

        $this->client($http, $this->coldCache())->discover(self::URL);
    }

    public function testIssuerMismatchToleratedWhenMatchNotRequired(): void
    {
        $url = 'https://login.microsoftonline.com/contoso.com/v2.0/.well-known/openid-configuration';
        $issuer = 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0';
        $http = $this->httpReturning($this->document(['issuer' => $issuer]));

        $metadata = $this->client($http, $this->coldCache())->discover($url, false);

        self::assertSame($issuer, $metadata->getIssuer());
    }

    public function testIssuerMismatchOnCachedDocumentThrows(): void
    {
        $cache = $this->createStub(FrontendInterface::class);
        $cache->method('load')->willReturn($this->document(['issuer' => 'https://evil.example.com']));

        $http = $this->createMock(ClientInterface::class);
        $http->expects(self::never())->method('get');

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('does not match');

        $this->client($http, $cache)->discover(self::URL);
    }

    public function testIssuerMismatchOnCachedDocumentToleratedWhenMatchNotRequired(): void
    {
        $cache = $this->createStub(FrontendInterface::class);
        $cache->method('load')->willReturn($this->document(['issuer' => 'https://other.example.com']));

        $metadata = $this->client($this->createStub(ClientInterface::class), $cache)
            ->discover(self::URL, false);

        self::assertSame('https://other.example.com', $metadata->getIssuer());
    }

    public function testNonStandardUrlThrowsWhenIssuerMatchRequired(): void
    {
        $http = $this->httpReturning($this->document(['issuer' => 'https://idp.example.com']));

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('cannot be verified');

        $this->client($http, $this->coldCache())->discover('https://idp.example.com/oidc/metadata.json');
    }

    public function testNonStandardUrlAllowedWhenMatchNotRequired(): void
    {
        $http = $this->httpReturning($this->document(['issuer' => 'https://idp.example.com']));

        $metadata = $this->client($http, $this->coldCache())
            ->discover('https://idp.example.com/oidc/metadata.json', false);

        self::assertSame('https://idp.example.com', $metadata->getIssuer());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidIssuerProvider(): array
    {
        return [
            'http' => ['http://dev.okta.com'],
            'query' => ['https://dev.okta.com?tenant=1'],
            'fragment' => ['https://dev.okta.com#x'],
        ];
    }

    #[DataProvider('invalidIssuerProvider')]
    public function testRejectsInvalidIssuerIdentifierEvenWithoutMatch(string $issuer): void
    {
        $http = $this->httpReturning($this->document(['issuer' => $issuer]));

        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('issuer');

        $this->client($http, $this->coldCache())->discover(self::URL, false);
    }

    public function testParsesSigningAlgorithmsAndIssParameterSupport(): void
    {
        $http = $this->httpReturning($this->document([
            'id_token_signing_alg_values_supported' => ['RS256', 'ES256'],
            'authorization_response_iss_parameter_supported' => true,
        ]));

        $metadata = $this->client($http, $this->coldCache())->discover(self::URL);

        self::assertSame(['RS256', 'ES256'], $metadata->getIdTokenSigningAlgValuesSupported());
        self::assertTrue($metadata->isAuthorizationResponseIssParameterSupported());
    }

    public function testIssParameterSupportRequiresStrictTrue(): void
    {
        $http = $this->httpReturning($this->document(['authorization_response_iss_parameter_supported' => 'true']));

        $metadata = $this->client($http, $this->coldCache())->discover(self::URL);

        self::assertFalse($metadata->isAuthorizationResponseIssParameterSupported());
        self::assertSame([], $metadata->getIdTokenSigningAlgValuesSupported());
    }

    private function httpReturning(string $body): ClientInterface
    {
        $http = $this->createStub(ClientInterface::class);
        $http->method('getStatus')->willReturn(200);
        $http->method('getBody')->willReturn($body);

        return $http;
    }

    private function coldCache(): FrontendInterface
    {
        $cache = $this->createStub(FrontendInterface::class);
        $cache->method('load')->willReturn(false);

        return $cache;
    }

    public function testCreatesBoundedHttpsClientPerRequest(): void
    {
        $first = $this->recordingHttp($log1, $this->document());
        $second = $this->recordingHttp($log2, $this->document());

        $factory = $this->createMock(ClientFactory::class);
        $factory->expects(self::exactly(2))->method('create')->willReturnOnConsecutiveCalls($first, $second);

        $client = new DiscoveryClient($factory, $this->coldCacheStub(), new Json());
        $client->discover(self::URL);
        $client->discover(self::URL);

        $this->assertBounded($log1);
        $this->assertBounded($log2);
        self::assertSame([], $log1['headers']);
    }

    public function testAppliesConfiguredTimeouts(): void
    {
        $http = $this->recordingHttp($log, $this->document());

        (new DiscoveryClient($this->factory($http), $this->coldCacheStub(), new Json(), 3600, 2, 7))
            ->discover(self::URL);

        $this->assertBounded($log, 2, 7);
    }

    public function testCacheHitCreatesNoHttpClient(): void
    {
        $cache = $this->createStub(FrontendInterface::class);
        $cache->method('load')->willReturn($this->document());

        $factory = $this->createMock(ClientFactory::class);
        $factory->expects(self::never())->method('create');

        (new DiscoveryClient($factory, $cache, new Json()))->discover(self::URL);
    }

    private function coldCacheStub(): FrontendInterface
    {
        $cache = $this->createStub(FrontendInterface::class);
        $cache->method('load')->willReturn(false);

        return $cache;
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
