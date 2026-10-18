<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Test\Unit\Model\Oidc;

use DmLab\SsoCore\Exception\IdTokenValidationException;
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
use PHPUnit\Framework\TestCase;

class JwksClientTest extends TestCase
{
    private const URI = 'https://dev.okta.com/oauth2/v1/keys';

    /**
     * @var string
     */
    private string $jwksJson;

    /**
     * @var JWK
     */
    private JWK $rotatedKey;

    /**
     * @var string
     */
    private string $rotatedJwksJson;

    protected function setUp(): void
    {
        $key = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig', 'kid' => 'k1']);
        $this->jwksJson = (string)json_encode(new JWKSet([$key->toPublic()]));
        $this->rotatedKey = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig', 'kid' => 'k2']);
        $this->rotatedJwksJson = (string)json_encode(new JWKSet([$this->rotatedKey->toPublic()]));
    }

    public function testFetchesParsesAndCachesOnMiss(): void
    {
        $cache = $this->createMock(FrontendInterface::class);
        $cache->method('load')->willReturn(false);
        $cache->expects(self::once())
            ->method('save')
            ->with($this->jwksJson, self::isString(), [], 3600);

        $http = $this->createMock(ClientInterface::class);
        $http->expects(self::once())->method('get')->with(self::URI);
        $http->method('getStatus')->willReturn(200);
        $http->method('getBody')->willReturn($this->jwksJson);

        $keySet = (new JwksClient($this->factory($http), $cache))->getKeySet(self::URI);

        self::assertInstanceOf(JWKSet::class, $keySet);
        self::assertCount(1, $keySet);
    }

    public function testUsesCacheOnHitWithoutHttpCall(): void
    {
        $cache = $this->createMock(FrontendInterface::class);
        $cache->method('load')->willReturn($this->jwksJson);
        $cache->expects(self::never())->method('save');

        $http = $this->createMock(ClientInterface::class);
        $http->expects(self::never())->method('get');

        $keySet = (new JwksClient($this->factory($http), $cache))->getKeySet(self::URI);

        self::assertCount(1, $keySet);
    }

    public function testThrowsOnHttpError(): void
    {
        $http = $this->createStub(ClientInterface::class);
        $http->method('getStatus')->willReturn(500);

        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('HTTP 500');

        (new JwksClient($this->factory($http), $this->coldCache()))->getKeySet(self::URI);
    }

    public function testThrowsOnMalformedJwks(): void
    {
        $http = $this->createStub(ClientInterface::class);
        $http->method('getStatus')->willReturn(200);
        $http->method('getBody')->willReturn('not json');

        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('malformed');

        (new JwksClient($this->factory($http), $this->coldCache()))->getKeySet(self::URI);
    }

    public function testThrowsWhenHttpClientFails(): void
    {
        $http = $this->createStub(ClientInterface::class);
        $http->method('get')->willThrowException(new \RuntimeException('timeout'));

        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('timeout');

        (new JwksClient($this->factory($http), $this->coldCache()))->getKeySet(self::URI);
    }

    private function coldCache(): FrontendInterface
    {
        $cache = $this->createStub(FrontendInterface::class);
        $cache->method('load')->willReturn(false);

        return $cache;
    }

    public function testCreatesBoundedHttpsClientPerRequest(): void
    {
        $first = $this->recordingHttp($log1, $this->jwksJson);
        $second = $this->recordingHttp($log2, $this->jwksJson);

        $factory = $this->createMock(ClientFactory::class);
        $factory->expects(self::exactly(2))->method('create')->willReturnOnConsecutiveCalls($first, $second);

        $client = new JwksClient($factory, $this->coldCache());
        $client->getKeySet(self::URI);
        $client->getKeySet(self::URI);

        $this->assertBounded($log1);
        $this->assertBounded($log2);
        self::assertSame([], $log1['headers']);
    }

    public function testAppliesConfiguredTimeouts(): void
    {
        $http = $this->recordingHttp($log, $this->jwksJson);

        (new JwksClient($this->factory($http), $this->coldCache(), 3600, 2, 7))->getKeySet(self::URI);

        $this->assertBounded($log, 2, 7);
    }

    public function testCacheHitCreatesNoHttpClient(): void
    {
        $cache = $this->createStub(FrontendInterface::class);
        $cache->method('load')->willReturn($this->jwksJson);

        $factory = $this->createMock(ClientFactory::class);
        $factory->expects(self::never())->method('create');

        (new JwksClient($factory, $cache))->getKeySet(self::URI);
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

    public function testKnownKidUsesCacheWithoutHttp(): void
    {
        $saves = [];
        $factory = $this->createMock(ClientFactory::class);
        $factory->expects(self::never())->method('create');

        $keySet = (new JwksClient($factory, $this->memoryCache($this->jwksJson, false, $saves)))
            ->getKeySetForToken(self::URI, $this->token(['alg' => 'RS256', 'kid' => 'k1']));

        self::assertTrue($keySet->has('k1'));
        self::assertSame([], $saves);
    }

    public function testUnknownKidRefetchesOnceAndOverwritesCache(): void
    {
        $saves = [];
        $http = $this->createMock(ClientInterface::class);
        $http->expects(self::once())->method('get')->with(self::URI);
        $http->method('getStatus')->willReturn(200);
        $http->method('getBody')->willReturn($this->rotatedJwksJson);

        $keySet = (new JwksClient($this->factory($http), $this->memoryCache($this->jwksJson, false, $saves)))
            ->getKeySetForToken(self::URI, $this->token(['alg' => 'RS256', 'kid' => 'k2']));

        self::assertTrue($keySet->has('k2'));
        $hash = hash('sha256', self::URI);
        self::assertSame(['1', 60], $saves['dmlab_ssocore_oidc_jwks_refetch_' . $hash] ?? null);
        self::assertSame([$this->rotatedJwksJson, 3600], $saves['dmlab_ssocore_oidc_jwks_' . $hash] ?? null);
    }

    public function testRefetchCooldownIsConfigurable(): void
    {
        $saves = [];
        $http = $this->recordingHttp($log, $this->rotatedJwksJson);

        (new JwksClient($this->factory($http), $this->memoryCache($this->jwksJson, false, $saves), 3600, 5, 10, 15))
            ->getKeySetForToken(self::URI, $this->token(['alg' => 'RS256', 'kid' => 'k2']));

        self::assertSame(['1', 15], $saves['dmlab_ssocore_oidc_jwks_refetch_' . hash('sha256', self::URI)] ?? null);
    }

    public function testUnknownKidDuringCooldownSkipsHttp(): void
    {
        $saves = [];
        $factory = $this->createMock(ClientFactory::class);
        $factory->expects(self::never())->method('create');

        $keySet = (new JwksClient($factory, $this->memoryCache($this->jwksJson, true, $saves)))
            ->getKeySetForToken(self::URI, $this->token(['alg' => 'RS256', 'kid' => 'k2']));

        self::assertFalse($keySet->has('k2'));
        self::assertTrue($keySet->has('k1'));
        self::assertSame([], $saves);
    }

    public function testUnknownKidOnColdCacheFetchesOnlyOnce(): void
    {
        $saves = [];
        $factory = $this->createMock(ClientFactory::class);
        $factory->expects(self::once())->method('create')->willReturn($this->recordingHttp($log, $this->jwksJson));

        $keySet = (new JwksClient($factory, $this->memoryCache(null, false, $saves)))
            ->getKeySetForToken(self::URI, $this->token(['alg' => 'RS256', 'kid' => 'k2']));

        self::assertFalse($keySet->has('k2'));
        self::assertArrayNotHasKey('dmlab_ssocore_oidc_jwks_refetch_' . hash('sha256', self::URI), $saves);
    }

    public function testHeaderWithoutKidReturnsCachedSet(): void
    {
        $saves = [];
        $factory = $this->createMock(ClientFactory::class);
        $factory->expects(self::never())->method('create');

        $keySet = (new JwksClient($factory, $this->memoryCache($this->jwksJson, false, $saves)))
            ->getKeySetForToken(self::URI, $this->token(['alg' => 'RS256']));

        self::assertTrue($keySet->has('k1'));
        self::assertSame([], $saves);
    }

    public function testMalformedTokenReturnsCachedSet(): void
    {
        $saves = [];
        $factory = $this->createMock(ClientFactory::class);
        $factory->expects(self::never())->method('create');

        $keySet = (new JwksClient($factory, $this->memoryCache($this->jwksJson, false, $saves)))
            ->getKeySetForToken(self::URI, 'not.a-jws');

        self::assertTrue($keySet->has('k1'));
    }

    public function testRefetchHttpFailureThrows(): void
    {
        $saves = [];
        $http = $this->createStub(ClientInterface::class);
        $http->method('getStatus')->willReturn(503);

        try {
            (new JwksClient($this->factory($http), $this->memoryCache($this->jwksJson, false, $saves)))
                ->getKeySetForToken(self::URI, $this->token(['alg' => 'RS256', 'kid' => 'k2']));
            self::fail('Expected IdTokenValidationException.');
        } catch (IdTokenValidationException $e) {
            self::assertStringContainsString('HTTP 503', $e->getMessage());
        }

        $hash = hash('sha256', self::URI);
        self::assertSame(['1', 60], $saves['dmlab_ssocore_oidc_jwks_refetch_' . $hash] ?? null);
        self::assertArrayNotHasKey('dmlab_ssocore_oidc_jwks_' . $hash, $saves);
    }

    /**
     * In-memory cache: optional warm JWKS document, optional refetch marker; records saves as [data, lifetime].
     *
     * @param array<string, array{0: string, 1: int|null}> $saves
     */
    private function memoryCache(?string $jwksJson, bool $markerPresent, array &$saves): FrontendInterface
    {
        $hash = hash('sha256', self::URI);
        $entries = [];
        if ($jwksJson !== null) {
            $entries['dmlab_ssocore_oidc_jwks_' . $hash] = $jwksJson;
        }
        if ($markerPresent) {
            $entries['dmlab_ssocore_oidc_jwks_refetch_' . $hash] = '1';
        }

        $cache = $this->createStub(FrontendInterface::class);
        $cache->method('load')->willReturnCallback(static fn(string $id) => $entries[$id] ?? false);
        $cache->method('save')->willReturnCallback(
            static function ($data, $id, $tags = [], $lifetime = null) use (&$saves): bool {
                $saves[$id] = [$data, $lifetime];

                return true;
            }
        );

        return $cache;
    }

    /**
     * Compact JWS signed by the rotated key with the given protected header.
     *
     * @param array<string, string> $header
     */
    private function token(array $header): string
    {
        $jws = (new JWSBuilder(new AlgorithmManager([new RS256()])))->create()
            ->withPayload('{"sub":"u1"}', false)
            ->addSignature($this->rotatedKey, $header, [])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    private function factory(ClientInterface $http): ClientFactory
    {
        $factory = $this->createStub(ClientFactory::class);
        $factory->method('create')->willReturn($http);

        return $factory;
    }
}
