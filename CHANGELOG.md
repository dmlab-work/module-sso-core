# Changelog

## 0.2.1

- Fixed: `state`, `nonce` and PKCE `code_verifier` were base64-encoded twice; now 43-char base64url tokens from 32 random bytes.
- Tested on Magento 2.4.9 and PHP 8.5.

## 0.2.0

### Breaking

- `discover()` enforces the §4.3 issuer match by default; pass `false` for presets whose `DiscoveryIssuerPolicyInterface` opts out.
- ID tokens without `iat` are rejected.
- `IdentityInterface` gains `isEmailVerified()`.
- `DiscoveryClient`/`JwksClient`/`TokenClient` take `ClientFactory $httpClientFactory` instead of `ClientInterface $httpClient`.
- Consumers must require `dmlab/module-sso-core ^0.2`.

### Added

- `IdentityInterface::isEmailVerified()` from `email_verified`; optional `EmailVerificationResolverInterface` for presets.
- ID-token `iat` (required) and `nbf` (optional) validated with the 60s leeway.
- Discovery `issuer` must match the discovery URL (OIDC Discovery §4.3); optional `DiscoveryIssuerPolicyInterface` opt-out.
- Fresh HTTP client per request via `ClientFactory`; connect 5s / total 10s timeouts, HTTPS-only.
- `JwksClient::getKeySetForToken()` refetches the JWKS on an unknown `kid` (60s cooldown).
- Optional `AuthorizationParamsProviderInterface`; `AuthorizationRequestFactory::create()` accepts `$extraParams`.
- Packaging: `ext-curl` requirement, OSL-3.0 headers, i18n phrases.

## 0.1.1

- Rebrand to the `dmlab` vendor and `DmLab` namespace.
