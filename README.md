# DmLab_SsoCore

> Shared OIDC engine for the DMLab SSO suite — the single dependency every login product builds on.

[![CI](https://github.com/dmlab-work/module-sso-core/actions/workflows/ci.yml/badge.svg)](https://github.com/dmlab-work/module-sso-core/actions/workflows/ci.yml) [![codecov](https://codecov.io/gh/dmlab-work/module-sso-core/graph/badge.svg)](https://codecov.io/gh/dmlab-work/module-sso-core) [![Packagist](https://img.shields.io/packagist/dt/dmlab/module-sso-core)](https://packagist.org/packages/dmlab/module-sso-core)
![License](https://img.shields.io/badge/license-OSL--3.0-green) ![Magento](https://img.shields.io/badge/Magento-2.4-orange) ![PHP](https://img.shields.io/badge/PHP-8.3--8.5-blue) ![Version](https://img.shields.io/badge/version-0.2.0-lightgrey)

The shared OIDC/SSO engine for the DMLab identity suite. It is installed
transitively by every login product (`admin-sso-okta`, `customer-sso-okta`, ...),
so you rarely require it directly.

## What it provides

Ships **protocol only** — no UI, no config, no secret storage. Products own
configuration and supply a small `ProviderPreset`; the engine does the OIDC work.
Scope v1 is **OIDC** (authorization-code + PKCE); SAML is a later phase.

- Generic OIDC client: discovery, authorization request, token exchange, ID-token
  validation against JWKS, claim → identity normalization.
- A stateless group/claim **mapping engine** (IdP values → target keys).
- A `ProviderPreset` contract so IdP differences (discovery URL, scopes, groups
  claim, branding) stay in a provider plugin module — one engine serves any
  compliant IdP.

## OIDC flow

1. **Discovery** — `DiscoveryClient::discover($url, $requireIssuerMatch = true)` fetches
   (and caches) `.well-known/openid-configuration` → `ProviderMetadata` (issuer,
   authorization, token, JWKS endpoints). Per OIDC Discovery §4.3 the `issuer` (minus a
   trailing `/`) must equal the URL prefix before `/.well-known/openid-configuration`; pass `false`
   when the preset's `DiscoveryIssuerPolicyInterface` opts out (e.g. Entra domain tenant).
2. **Authorization request** — `AuthorizationRequestFactory::create()` builds the
   redirect URL with `state`, `nonce`, a PKCE `S256` challenge, and optional preset
   `$extraParams` (reserved OIDC keys rejected). It returns an
   `AuthorizationRequest` (implements `AuthorizationStateInterface`); the consumer
   persists that state via `AuthorizationStateStorageInterface` before redirecting.
3. **Callback** — the consumer reloads the state with `consume($state)` (one-time;
   replay-protected).
4. **Token exchange** — `TokenClient::exchangeCode()` redeems the code with the PKCE
   verifier at the token endpoint → `TokenResponse` (carries the `id_token`).
5. **ID-token validation** — `JwksClient::getKeySetForToken($jwksUri, $idToken)` resolves
   the JWKS and refetches once when the token's `kid` is unknown (IdP key rotation; at most
   one refetch per 60s cooldown). `IdTokenValidator::validate()` verifies the JWS signature
   (asymmetric algorithms only — no `none`/`HS*`) and `iss`/`aud`/`azp`/`exp`/`iat`/`nbf`/
   `nonce` (60s leeway on time claims) → validated claims.
6. **Normalization** — `IdentityFactory::create($claims, $preset)` maps `sub`,
   `email`, `name`, `email_verified`, and the preset's groups claim into an
   `IdentityInterface`.
7. **Mapping** — `MappingEngine::resolve($groups, $rules, $default)` turns IdP groups
   into target keys (e.g. Magento role ids).

`state` guards CSRF, `nonce` guards replay, PKCE binds the code to the client that
started the flow.

Outbound HTTP (discovery, JWKS, token) uses a fresh HTTPS-only client per request with a
5s connect / 10s total timeout — override `connectTimeout`, `timeout`, `refetchCooldown`
(JWKS) via `etc/di.xml` arguments.

## The ProviderPreset contract

`Api/ProviderPresetInterface` is the only IdP-specific surface. A provider plugin
module (e.g. `admin-sso-okta`) implements it and registers the preset into the
capability core's `PresetRegistry`. sso-core itself holds no registry and no
IdP-specific code.

Optional capabilities are separate interfaces a preset may also implement (see Public API).

| Method | Purpose |
|---|---|
| `getCode()` | Stable machine code (`okta`, `azure`). |
| `getLabel()` | Human-readable IdP name for the admin UI. |
| `buildDiscoveryUrl(array $config)` | Discovery URL from the product's resolved config. |
| `getDefaultScopes()` | Scopes to request (always includes `openid`). |
| `getGroupsClaim()` | Claim carrying groups (`groups`), or `null`. |
| `getButtonLabel()` | Login-button label. |
| `getButtonIconUrl()` | Login-button icon URL, or `null`. |

## How products consume the engine

Install pulls the core transitively:

```
composer require dmlab/module-admin-sso-okta   # pulls dmlab/module-sso-core
```

A product wires the flow using only the public surface — build the auth URL from
its preset, validate the ID token, normalize an Identity, map groups:

```php
$metadata = $discoveryClient->discover(
    $preset->buildDiscoveryUrl($config),
    !$preset instanceof DiscoveryIssuerPolicyInterface || $preset->requiresIssuerMatch($config)
);
$authRequest = $authorizationRequestFactory->create(
    $metadata->getAuthorizationEndpoint(),
    $clientId,
    $redirectUri,
    $preset->getDefaultScopes(),
    $preset instanceof AuthorizationParamsProviderInterface
        ? $preset->getAuthorizationParams($config) : []
);
$stateStorage->save($authRequest);           // persist before redirect
// redirect user to $authRequest->getUrl()

// --- on callback ---
$state  = $stateStorage->consume($stateParam);
$tokens = $tokenClient->exchangeCode(
    $metadata->getTokenEndpoint(),
    $code,
    $redirectUri,
    $clientId,
    $state->getCodeVerifier(),
    $clientSecret
);
$claims = $idTokenValidator->validate(
    $tokens->getIdToken(),
    $jwksClient->getKeySetForToken($metadata->getJwksUri(), $tokens->getIdToken()),
    $metadata->getIssuer(),
    $clientId,
    $state->getNonce()
);
$identity = $identityFactory->create($claims, $preset);
// adopt an existing account by email only if $identity->isEmailVerified()
$roles    = $mappingEngine->resolve($identity->getGroups(), $groupRules, $defaultRole);
```

The engine never stores secrets — the product passes already-resolved client
id/secret and owns the `AuthorizationStateStorageInterface` implementation (session,
cache, ...).

## Public API (`Api/`)

Stable contracts products depend on. Full method docs live in the interface files.

| Interface | Role |
|---|---|
| `Api/ProviderPresetInterface` | IdP preset a product supplies to the engine. |
| `Api/EmailVerificationResolverInterface` | Optional preset: `resolveEmailVerified($claims)` overrides `email_verified` (`null` = standard claim). |
| `Api/DiscoveryIssuerPolicyInterface` | Optional preset: `requiresIssuerMatch($config)` — `false` skips the §4.3 issuer check. |
| `Api/AuthorizationParamsProviderInterface` | Optional preset: `getAuthorizationParams($config)` — extra auth params (`hd`, `domain_hint`). |
| `Api/Data/IdentityInterface` | Provider-agnostic normalized identity (`getSubjectId`, `getEmail`, `getName`, `getGroups`, `isEmailVerified`). |
| `Api/AuthorizationStateStorageInterface` | Product-owned persistence of the one-time auth state (`save`, `consume`). |
| `Api/Data/AuthorizationStateInterface` | The one-time state itself (`getState`, `getNonce`, `getCodeVerifier`). |

## Requirements

- Magento Open Source / Adobe Commerce **2.4.x**
- PHP **8.3 – 8.5** with `ext-curl`
- `magento/framework >=103.0`
- `web-token/jwt-framework ^4.0`

## Part of the DMLab identity suite

| Repo | Role |
|------|------|
| `sso-core` | Shared OIDC engine (installed automatically) |
| `admin-sso` · `admin-sso-<idp>` | Admin-panel SSO login |
| `customer-sso` · `customer-sso-<idp>` | Storefront SSO login |
| `admin-scim` · `admin-scim-<idp>` | Admin-user provisioning (SCIM 2.0) |

## License

[OSL-3.0](LICENSE) © DMLab. Commercial licensing and support: <https://dmlab.work>.
