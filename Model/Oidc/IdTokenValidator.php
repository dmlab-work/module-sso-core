<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\SsoCore\Model\Oidc;

use DmLab\SsoCore\Exception\IdTokenValidationException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Magento\Framework\Serialize\SerializerInterface;

/**
 * Validates an OIDC ID token: verifies the JWS signature against the IdP's JWKS,
 * then checks the `iss`, `aud`/`azp`, `exp`, `iat`, `nbf`, and `nonce` claims. Returns the validated
 * claim set for the normalizer to consume.
 */
class IdTokenValidator
{
    /**
     * Signature algorithms accepted for ID tokens. `none`/`HS*` are intentionally
     * absent — an asymmetric signature is required.
     */
    private const ALLOWED_ALGORITHMS = [RS256::class, RS384::class, RS512::class, ES256::class, PS256::class];

    /**
     * Clock skew allowance (seconds) applied to `exp`, `iat`, and `nbf`.
     */
    private const LEEWAY = 60;

    /**
     * Inject the JSON serializer used to decode the token payload.
     *
     * @param SerializerInterface $serializer
     */
    public function __construct(
        private readonly SerializerInterface $serializer
    ) {
    }

    /**
     * Validate the ID token signature and claims, returning the claim set.
     *
     * @param string $idToken
     * @param JWKSet $keySet
     * @param string $expectedIssuer
     * @param string $expectedAudience
     * @param string $expectedNonce
     * @param int|null $now
     * @return array<string, mixed> validated claims
     * @throws IdTokenValidationException
     */
    public function validate(
        string $idToken,
        JWKSet $keySet,
        string $expectedIssuer,
        string $expectedAudience,
        string $expectedNonce,
        ?int $now = null
    ): array {
        $now ??= time();

        $jws = $this->deserialize($idToken);

        // verifyWithKeySet throws (not returns false) for an unsupported/absent `alg`
        // header — e.g. an attacker-forged `HS256`/`none` token — or an empty keyset.
        // Treat any such failure as a rejected token, not an uncaught error.
        try {
            $verified = $this->verifier()->verifyWithKeySet($jws, $keySet, 0);
        } catch (\Throwable $e) {
            throw new IdTokenValidationException('ID token signature could not be verified.', 0, $e);
        }

        if (!$verified) {
            throw new IdTokenValidationException('ID token signature verification failed.');
        }

        $claims = $this->decodeClaims($jws->getPayload());

        $this->assertIssuer($claims, $expectedIssuer);
        $this->assertAudience($claims, $expectedAudience);
        $this->assertNotExpired($claims, $now);
        $this->assertIssuedAt($claims, $now);
        $this->assertNotBefore($claims, $now);
        $this->assertNonce($claims, $expectedNonce);

        return $claims;
    }

    /**
     * Build a JWS verifier limited to the allowed asymmetric algorithms.
     */
    private function verifier(): JWSVerifier
    {
        $algorithms = array_map(static fn(string $class) => new $class(), self::ALLOWED_ALGORITHMS);

        return new JWSVerifier(new AlgorithmManager($algorithms));
    }

    /**
     * Deserialize the compact JWS string.
     *
     * @param string $idToken
     */
    private function deserialize(string $idToken)
    {
        try {
            return (new CompactSerializer())->unserialize($idToken);
        } catch (\Throwable $e) {
            throw new IdTokenValidationException('ID token is not a well-formed compact JWS.', 0, $e);
        }
    }

    /**
     * Decode the JWS payload into a claims array.
     *
     * @param string|null $payload
     * @return array<string, mixed>
     */
    private function decodeClaims(?string $payload): array
    {
        if ($payload === null || $payload === '') {
            throw new IdTokenValidationException('ID token has an empty payload.');
        }

        try {
            $claims = $this->serializer->unserialize($payload);
        } catch (\Throwable $e) {
            throw new IdTokenValidationException('ID token payload is not valid JSON.', 0, $e);
        }

        if (!is_array($claims)) {
            throw new IdTokenValidationException('ID token payload is not a JSON object.');
        }

        return $claims;
    }

    /**
     * Assert the token issuer matches the expected value.
     *
     * @param array<string,mixed> $claims
     * @param string $expectedIssuer
     */
    private function assertIssuer(array $claims, string $expectedIssuer): void
    {
        if (($claims['iss'] ?? null) !== $expectedIssuer) {
            throw new IdTokenValidationException('ID token "iss" does not match the expected issuer.');
        }
    }

    /**
     * Assert the token audience includes the expected value.
     *
     * @param array<string,mixed> $claims
     * @param string $expectedAudience
     */
    private function assertAudience(array $claims, string $expectedAudience): void
    {
        $aud = $claims['aud'] ?? null;
        $audiences = is_array($aud) ? $aud : [$aud];

        if (!in_array($expectedAudience, $audiences, true)) {
            throw new IdTokenValidationException('ID token "aud" does not include the expected audience.');
        }

        // OIDC Core §3.1.3.7: with multiple audiences the `azp` (authorized party)
        // claim must be present and must equal the expected audience (client id).
        if (count($audiences) > 1 && ($claims['azp'] ?? null) !== $expectedAudience) {
            throw new IdTokenValidationException('ID token "azp" does not match for a multi-audience token.');
        }
    }

    /**
     * Assert the token has not expired (with leeway).
     *
     * @param array<string,mixed> $claims
     * @param int $now
     */
    private function assertNotExpired(array $claims, int $now): void
    {
        $exp = $claims['exp'] ?? null;
        if (!$this->isNumericDate($exp)) {
            throw new IdTokenValidationException('ID token is missing a valid "exp" claim.');
        }

        if ((int)$exp + self::LEEWAY <= $now) {
            throw new IdTokenValidationException('ID token has expired.');
        }
    }

    /**
     * Assert the required `iat` claim is not in the future (with leeway).
     *
     * @param array<string,mixed> $claims
     * @param int $now
     */
    private function assertIssuedAt(array $claims, int $now): void
    {
        $iat = $claims['iat'] ?? null;
        if (!$this->isNumericDate($iat)) {
            throw new IdTokenValidationException('ID token is missing a valid "iat" claim.');
        }

        if ((int)$iat > $now + self::LEEWAY) {
            throw new IdTokenValidationException('ID token "iat" is in the future.');
        }
    }

    /**
     * Assert the optional `nbf` claim, when present, is not in the future (with leeway).
     *
     * @param array<string,mixed> $claims
     * @param int $now
     */
    private function assertNotBefore(array $claims, int $now): void
    {
        if (!array_key_exists('nbf', $claims)) {
            return;
        }

        $nbf = $claims['nbf'];
        if (!$this->isNumericDate($nbf)) {
            throw new IdTokenValidationException('ID token has an invalid "nbf" claim.');
        }

        if ((int)$nbf > $now + self::LEEWAY) {
            throw new IdTokenValidationException('ID token is not valid yet ("nbf").');
        }
    }

    /**
     * Check a claim is an integer or a digit-only string.
     *
     * @param mixed $value
     */
    private function isNumericDate(mixed $value): bool
    {
        return is_int($value) || (is_string($value) && ctype_digit($value));
    }

    /**
     * Assert the token nonce matches the expected value.
     *
     * @param array<string,mixed> $claims
     * @param string $expectedNonce
     */
    private function assertNonce(array $claims, string $expectedNonce): void
    {
        if (($claims['nonce'] ?? null) !== $expectedNonce) {
            throw new IdTokenValidationException('ID token "nonce" does not match the expected value.');
        }
    }
}
