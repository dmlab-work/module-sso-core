# Changelog

## 0.2.3

- Added: `ProviderMetadata::getEndSessionEndpoint()` (discovered `end_session_endpoint`, https only, else `null`).
- Added: `LogoutUrlBuilder::build()` for OpenID Connect RP-Initiated Logout 1.0 (`id_token_hint`, `client_id`, `post_logout_redirect_uri`, `state`).

## 0.2.2

### Breaking

- `AuthorizationStateInterface` gains `getIssuer()`; conflicts with `dmlab/module-admin-sso` / `dmlab/module-customer-sso` < 0.2.2.
- `IdentityFactory::create()` requires a non-empty `iss` claim.
- Token endpoint auth defaults to `client_secret_basic`; `client_secret_post` only when the IdP advertises just that.
- ID tokens with untrusted extra `aud` values, any `crit` header, or `iat` older than 600s (+60s leeway) are rejected.
- `discover()` with the issuer match rejects URLs not ending in `/.well-known/openid-configuration`; the discovered `issuer` must be https without query/fragment.
- `max_age`, `request`, `request_uri` are reserved authorization params.
- `MappingEngine::resolve()` orders targets by rule order, not IdP group order.

### Added

- `IdentityInterface::getIssuer()`, `hasDistributedClaim()`, `hasDistributedGroups()` (distributed `_claim_names`, e.g. Entra groups overage).
- `AuthorizationResponseValidator::validateIssuer()` (RFC 9207 `iss`, mix-up defense); `AuthorizationRequestFactory::create()` accepts `$issuer`.
- `IdTokenValidator::validateForProvider()`: discovered issuer, JWKS and signing algs; one JWKS refetch for kid-less tokens on signature failure. `maxIatAge` di argument.
- ES384/ES512/PS384/PS512 and EdDSA (with ext-sodium) ID-token signatures, intersected with the discovered algs.
- `ProviderMetadata` exposes `token_endpoint_auth_methods_supported`, `id_token_signing_alg_values_supported`, `authorization_response_iss_parameter_supported`.
- Fixed: fractional NumericDate `exp`/`iat`/`nbf` accepted.

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
