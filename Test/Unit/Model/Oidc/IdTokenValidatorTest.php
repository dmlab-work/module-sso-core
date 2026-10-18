<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Test\Unit\Model\Oidc;

use DmLab\SsoCore\Exception\IdTokenValidationException;
use DmLab\SsoCore\Model\Oidc\IdTokenValidator;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Magento\Framework\Serialize\Serializer\Json;
use PHPUnit\Framework\TestCase;

class IdTokenValidatorTest extends TestCase
{
    private const ISSUER = 'https://dev.okta.com';
    private const AUDIENCE = 'client-abc';
    private const NONCE = 'nonce-xyz';
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

    private function validator(): IdTokenValidator
    {
        return new IdTokenValidator(new Json());
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function claims(array $overrides = []): array
    {
        return array_merge([
            'iss' => self::ISSUER,
            'aud' => self::AUDIENCE,
            'sub' => 'user-123',
            'email' => 'user@example.com',
            'nonce' => self::NONCE,
            'iat' => self::NOW,
            'exp' => self::NOW + 300,
        ], $overrides);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function mint(array $claims, ?JWK $signingKey = null): string
    {
        $signingKey ??= $this->privateKey;
        $builder = new JWSBuilder(new AlgorithmManager([new RS256()]));
        $jws = $builder->create()
            ->withPayload((string)json_encode($claims), false)
            ->addSignature($signingKey, ['alg' => 'RS256', 'kid' => $signingKey->get('kid')], [])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    private function validate(string $token): array
    {
        return $this->validator()->validate(
            $token,
            $this->keySet,
            self::ISSUER,
            self::AUDIENCE,
            self::NONCE,
            self::NOW
        );
    }

    public function testValidatesGoodTokenAndReturnsClaims(): void
    {
        $claims = $this->validate($this->mint($this->claims()));

        self::assertSame('user-123', $claims['sub']);
        self::assertSame('user@example.com', $claims['email']);
        self::assertSame(self::NONCE, $claims['nonce']);
    }

    public function testAcceptsAudienceArrayContainingExpected(): void
    {
        $claims = $this->validate($this->mint(
            $this->claims(['aud' => ['someone-else', self::AUDIENCE], 'azp' => self::AUDIENCE])
        ));

        self::assertSame(self::AUDIENCE, $claims['aud'][1]);
    }

    public function testRejectsMultiAudienceWithoutMatchingAzp(): void
    {
        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('azp');

        // Multiple audiences but no azp — OIDC Core §3.1.3.7 requires azp === client id.
        $this->validate($this->mint($this->claims(['aud' => ['someone-else', self::AUDIENCE]])));
    }

    public function testRejectsTamperedSignature(): void
    {
        $token = $this->mint($this->claims());
        [$header, $payload, $signature] = explode('.', $token);

        // Flip a bit in the decoded signature bytes, then re-encode: keeps the JWS
        // well-formed (correct length/charset) so it reaches — and fails — signature
        // verification deterministically, rather than breaking deserialization.
        $bytes = (string)base64_decode(strtr($signature, '-_', '+/'), true);
        $bytes[0] = chr(ord($bytes[0]) ^ 0x01);
        $tamperedSignature = rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
        $tampered = $header . '.' . $payload . '.' . $tamperedSignature;

        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('signature');

        $this->validate($tampered);
    }

    public function testRejectsTokenSignedByUnknownKey(): void
    {
        $foreignKey = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig', 'kid' => 'foreign']);

        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('signature');

        $this->validate($this->mint($this->claims(), $foreignKey));
    }

    public function testRejectsHs256AlgorithmConfusion(): void
    {
        // Classic JWT alg-confusion: forge an HMAC-signed token. HS256 is not in the
        // validator's asymmetric allow-list, so it must be cleanly rejected — never
        // let a raw library exception escape validate().
        $secret = JWKFactory::createOctKey(256, ['alg' => 'HS256', 'use' => 'sig', 'kid' => 'k1']);
        $builder = new JWSBuilder(new AlgorithmManager([new HS256()]));
        $jws = $builder->create()
            ->withPayload((string)json_encode($this->claims()), false)
            ->addSignature($secret, ['alg' => 'HS256', 'kid' => 'k1'], [])
            ->build();
        $token = (new CompactSerializer())->serialize($jws, 0);

        $this->expectException(IdTokenValidationException::class);

        $this->validate($token);
    }

    public function testRejectsNoneAlgorithm(): void
    {
        // Hand-craft an unsigned `alg: none` token; must be rejected, not throw raw.
        $b64 = static fn(array $data): string =>
            rtrim(strtr(base64_encode((string)json_encode($data)), '+/', '-_'), '=');
        $token = $b64(['alg' => 'none', 'typ' => 'JWT']) . '.' . $b64($this->claims()) . '.';

        $this->expectException(IdTokenValidationException::class);

        $this->validate($token);
    }

    public function testAcceptsTokenExpiredWithinLeeway(): void
    {
        // Expired 30s ago — inside the 60s clock-skew leeway, so still accepted.
        $claims = $this->validate($this->mint($this->claims(['exp' => self::NOW - 30])));

        self::assertSame('user-123', $claims['sub']);
    }

    public function testRejectsTokenExpiredBeyondLeeway(): void
    {
        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('expired');

        // Expired 90s ago — past the 60s leeway.
        $this->validate($this->mint($this->claims(['exp' => self::NOW - 90])));
    }

    public function testAcceptsNumericStringExp(): void
    {
        $claims = $this->validate($this->mint($this->claims(['exp' => (string)(self::NOW + 300)])));

        self::assertSame('user-123', $claims['sub']);
    }

    public function testRejectsWrongIssuer(): void
    {
        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('iss');

        $this->validate($this->mint($this->claims(['iss' => 'https://evil.example'])));
    }

    public function testRejectsWrongAudience(): void
    {
        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('aud');

        $this->validate($this->mint($this->claims(['aud' => 'other-client'])));
    }

    public function testRejectsExpiredToken(): void
    {
        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('expired');

        $this->validate($this->mint($this->claims(['exp' => self::NOW - 1000])));
    }

    public function testRejectsMissingExp(): void
    {
        $claims = $this->claims();
        unset($claims['exp']);

        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('exp');

        $this->validate($this->mint($claims));
    }

    public function testAcceptsNumericStringIat(): void
    {
        $claims = $this->validate($this->mint($this->claims(['iat' => (string)self::NOW])));

        self::assertSame((string)self::NOW, $claims['iat']);
    }

    public function testRejectsMissingIat(): void
    {
        $claims = $this->claims();
        unset($claims['iat']);

        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('iat');

        $this->validate($this->mint($claims));
    }

    public function testRejectsNonNumericIat(): void
    {
        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('iat');

        $this->validate($this->mint($this->claims(['iat' => '2023-11-14T22:13:20Z'])));
    }

    public function testAcceptsIatInFutureWithinLeeway(): void
    {
        $claims = $this->validate($this->mint($this->claims(['iat' => self::NOW + 60])));

        self::assertSame(self::NOW + 60, $claims['iat']);
    }

    public function testRejectsIatInFutureBeyondLeeway(): void
    {
        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('"iat" is in the future');

        $this->validate($this->mint($this->claims(['iat' => self::NOW + 61])));
    }

    public function testAcceptsAbsentNbf(): void
    {
        $claims = $this->validate($this->mint($this->claims()));

        self::assertArrayNotHasKey('nbf', $claims);
    }

    public function testAcceptsNbfInFutureWithinLeeway(): void
    {
        $claims = $this->validate($this->mint($this->claims(['nbf' => self::NOW + 60])));

        self::assertSame(self::NOW + 60, $claims['nbf']);
    }

    public function testRejectsNbfInFutureBeyondLeeway(): void
    {
        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('nbf');

        $this->validate($this->mint($this->claims(['nbf' => self::NOW + 61])));
    }

    public function testRejectsNonNumericNbf(): void
    {
        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('nbf');

        $this->validate($this->mint($this->claims(['nbf' => null])));
    }

    public function testRejectsNonceMismatch(): void
    {
        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('nonce');

        $this->validate($this->mint($this->claims(['nonce' => 'wrong-nonce'])));
    }

    public function testRejectsMalformedToken(): void
    {
        $this->expectException(IdTokenValidationException::class);
        $this->expectExceptionMessage('compact JWS');

        $this->validate('not-a-jwt');
    }
}
