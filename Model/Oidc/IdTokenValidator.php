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
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Jose\Component\Signature\JWS;
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
     * absent — an asymmetric signature is required. EdDSA is added when ext-sodium is loaded.
     */
    private const ALLOWED_ALGORITHMS = [
        RS256::class,
        RS384::class,
        RS512::class,
        ES256::class,
        ES384::class,
        ES512::class,
        PS256::class,
        PS384::class,
        PS512::class,
    ];

    /**
     * Clock skew allowance (seconds) applied to `exp`, `iat`, and `nbf`.
     */
    private const LEEWAY = 60;

    /**
     * Inject the JSON serializer, the JWKS client, and the max accepted `iat` age (seconds, 0 = unlimited).
     *
     * @param SerializerInterface $serializer
     * @param JwksClient|null $jwksClient required by {@see validateForProvider()}
     * @param int $maxIatAge
     */
    public function __construct(
        private readonly SerializerInterface $serializer,
        private readonly ?JwksClient $jwksClient = null,
        private readonly int $maxIatAge = 600
    ) {
    }

    /**
     * Validate the ID token against the discovered provider, resolving its JWKS.
     *
     * Uses the discovered issuer, JWKS and signing algorithms. A kid-less token that fails
     * verification triggers one rate-limited JWKS refetch (OIDC Core §10.1.1).
     *
     * @param string $idToken
     * @param ProviderMetadata $metadata
     * @param string $clientId expected audience
     * @param string $expectedNonce
     * @param string[] $trustedAudiences extra `aud` values accepted besides the client id
     * @param int|null $now
     * @return array<string, mixed> validated claims
     * @throws IdTokenValidationException
     */
    public function validateForProvider(
        string $idToken,
        ProviderMetadata $metadata,
        string $clientId,
        string $expectedNonce,
        array $trustedAudiences = [],
        ?int $now = null
    ): array {
        if ($this->jwksClient === null) {
            throw new \LogicException('IdTokenValidator::validateForProvider() requires a JwksClient.');
        }

        $jws = $this->deserialize($idToken);
        $this->assertNoCriticalHeaders($jws);

        $jwksUri = $metadata->getJwksUri();
        $algorithms = $metadata->getIdTokenSigningAlgValuesSupported();
        try {
            $this->verifySignature($jws, $this->jwksClient->getKeySetForToken($jwksUri, $idToken), $algorithms);
        } catch (IdTokenValidationException $e) {
            $refetched = $this->hasKid($jws) ? null : $this->jwksClient->refetchKeySet($jwksUri);
            if ($refetched === null) {
                throw $e;
            }
            $this->verifySignature($jws, $refetched, $algorithms);
        }

        return $this->validateClaims(
            $jws,
            $metadata->getIssuer(),
            $clientId,
            $expectedNonce,
            $trustedAudiences,
            $now ?? time()
        );
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
     * @param string[] $trustedAudiences extra `aud` values accepted besides the expected audience
     * @param string[] $allowedAlgorithms discovered `id_token_signing_alg_values_supported`; empty = engine defaults
     * @return array<string, mixed> validated claims
     * @throws IdTokenValidationException
     */
    public function validate(
        string $idToken,
        JWKSet $keySet,
        string $expectedIssuer,
        string $expectedAudience,
        string $expectedNonce,
        ?int $now = null,
        array $trustedAudiences = [],
        array $allowedAlgorithms = []
    ): array {
        $jws = $this->deserialize($idToken);
        $this->assertNoCriticalHeaders($jws);
        $this->verifySignature($jws, $keySet, $allowedAlgorithms);

        return $this->validateClaims(
            $jws,
            $expectedIssuer,
            $expectedAudience,
            $expectedNonce,
            $trustedAudiences,
            $now ?? time()
        );
    }

    /**
     * Check the claims of a signature-verified JWS.
     *
     * @param JWS $jws
     * @param string $expectedIssuer
     * @param string $expectedAudience
     * @param string $expectedNonce
     * @param string[] $trustedAudiences
     * @param int $now
     * @return array<string, mixed>
     */
    private function validateClaims(
        JWS $jws,
        string $expectedIssuer,
        string $expectedAudience,
        string $expectedNonce,
        array $trustedAudiences,
        int $now
    ): array {
        $claims = $this->decodeClaims($jws->getPayload());

        $this->assertIssuer($claims, $expectedIssuer);
        $this->assertAudience($claims, $expectedAudience, $trustedAudiences);
        $this->assertNotExpired($claims, $now);
        $this->assertIssuedAt($claims, $now);
        $this->assertNotBefore($claims, $now);
        $this->assertNonce($claims, $expectedNonce);

        return $claims;
    }

    /**
     * Verify the JWS signature with the allowed algorithms.
     *
     * @param JWS $jws
     * @param JWKSet $keySet
     * @param string[] $allowedAlgorithms
     */
    private function verifySignature(JWS $jws, JWKSet $keySet, array $allowedAlgorithms): void
    {
        $verifier = $this->verifier($allowedAlgorithms);

        // verifyWithKeySet throws (not returns false) for an unsupported/absent `alg`
        // header — e.g. an attacker-forged `HS256`/`none` token — or an empty keyset.
        // Treat any such failure as a rejected token, not an uncaught error.
        try {
            $verified = $verifier->verifyWithKeySet($jws, $keySet, 0);
        } catch (\Throwable $e) {
            throw new IdTokenValidationException('ID token signature could not be verified.', 0, $e);
        }

        if (!$verified) {
            throw new IdTokenValidationException('ID token signature verification failed.');
        }
    }

    /**
     * Build a JWS verifier limited to the engine's asymmetric algorithms, intersected with the IdP's.
     *
     * @param string[] $allowedAlgorithms
     */
    private function verifier(array $allowedAlgorithms): JWSVerifier
    {
        $algorithms = array_values(array_filter(
            $this->supportedAlgorithms(),
            static fn(SignatureAlgorithm $algorithm) => $allowedAlgorithms === []
                || in_array($algorithm->name(), $allowedAlgorithms, true)
        ));
        if ($algorithms === []) {
            throw new IdTokenValidationException(sprintf(
                'None of the IdP signing algorithms (%s) is accepted for ID tokens.',
                implode(', ', $allowedAlgorithms)
            ));
        }

        return new JWSVerifier(new AlgorithmManager($algorithms));
    }

    /**
     * Instantiate the engine's accepted signature algorithms.
     *
     * @return SignatureAlgorithm[]
     */
    private function supportedAlgorithms(): array
    {
        $algorithms = array_map(static fn(string $class) => new $class(), self::ALLOWED_ALGORITHMS);
        if (extension_loaded('sodium')) {
            $algorithms[] = new EdDSA();
        }

        return $algorithms;
    }

    /**
     * Deserialize the compact JWS string.
     *
     * @param string $idToken
     */
    private function deserialize(string $idToken): JWS
    {
        try {
            return (new CompactSerializer())->unserialize($idToken);
        } catch (\Throwable $e) {
            throw new IdTokenValidationException('ID token is not a well-formed compact JWS.', 0, $e);
        }
    }

    /**
     * Reject any `crit` header: the engine implements no JWS extensions (RFC 7515 §4.1.11).
     *
     * @param JWS $jws
     */
    private function assertNoCriticalHeaders(JWS $jws): void
    {
        $signature = $jws->getSignature(0);
        if ($signature->hasProtectedHeaderParameter('crit') || $signature->hasHeaderParameter('crit')) {
            throw new IdTokenValidationException('ID token uses unsupported critical header extensions ("crit").');
        }
    }

    /**
     * Whether the JWS protected header carries a non-empty `kid`.
     *
     * @param JWS $jws
     */
    private function hasKid(JWS $jws): bool
    {
        $signature = $jws->getSignature(0);
        $kid = $signature->hasProtectedHeaderParameter('kid')
            ? $signature->getProtectedHeaderParameter('kid')
            : null;

        return is_string($kid) && $kid !== '';
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
     * Assert the audience includes the expected value and nothing untrusted (OIDC Core §3.1.3.7).
     *
     * @param array<string,mixed> $claims
     * @param string $expectedAudience
     * @param string[] $trustedAudiences
     */
    private function assertAudience(array $claims, string $expectedAudience, array $trustedAudiences): void
    {
        $aud = $claims['aud'] ?? null;
        $audiences = is_array($aud) ? array_values($aud) : [$aud];

        if (!in_array($expectedAudience, $audiences, true)) {
            throw new IdTokenValidationException('ID token "aud" does not include the expected audience.');
        }

        foreach ($audiences as $audience) {
            if ($audience !== $expectedAudience && !in_array($audience, $trustedAudiences, true)) {
                throw new IdTokenValidationException('ID token "aud" contains an untrusted audience.');
            }
        }

        // With multiple audiences the `azp` (authorized party) claim must be present
        // and must equal the expected audience (client id).
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
        $exp = $this->numericDate($claims['exp'] ?? null);
        if ($exp === null) {
            throw new IdTokenValidationException('ID token is missing a valid "exp" claim.');
        }

        if ($exp + self::LEEWAY <= $now) {
            throw new IdTokenValidationException('ID token has expired.');
        }
    }

    /**
     * Assert the required `iat` claim is neither in the future nor older than `maxIatAge` (with leeway).
     *
     * @param array<string,mixed> $claims
     * @param int $now
     */
    private function assertIssuedAt(array $claims, int $now): void
    {
        $iat = $this->numericDate($claims['iat'] ?? null);
        if ($iat === null) {
            throw new IdTokenValidationException('ID token is missing a valid "iat" claim.');
        }

        if ($iat > $now + self::LEEWAY) {
            throw new IdTokenValidationException('ID token "iat" is in the future.');
        }

        if ($this->maxIatAge > 0 && $iat + $this->maxIatAge + self::LEEWAY < $now) {
            throw new IdTokenValidationException('ID token "iat" is too far in the past.');
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

        $nbf = $this->numericDate($claims['nbf']);
        if ($nbf === null) {
            throw new IdTokenValidationException('ID token has an invalid "nbf" claim.');
        }

        if ($nbf > $now + self::LEEWAY) {
            throw new IdTokenValidationException('ID token is not valid yet ("nbf").');
        }
    }

    /**
     * Parse a NumericDate (RFC 7519 §2: seconds, possibly fractional); also accepts a numeric string.
     *
     * @param mixed $value
     */
    private function numericDate(mixed $value): ?float
    {
        if (is_int($value) || (is_float($value) && is_finite($value))) {
            return (float)$value;
        }

        if (is_string($value) && preg_match('/^\d+(\.\d+)?$/', $value) === 1) {
            return (float)$value;
        }

        return null;
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
