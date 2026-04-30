# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- `@o3co/auth-provider-core/testing` subpath. Exposes the
  `makeValidCoreConfig` / `makeValidFullSections` / `makeValidAppConfig`
  fixture factories so sibling packages and downstream test suites can
  build a schema-valid config baseline without re-implementing it. The
  subpath is consumer-test-only — production runtime code MUST NOT
  import from it.
- `@o3co/auth-provider-federation-google` package with `createGoogleProvider()` and `registerGoogleFederation(factory)`.
- `@o3co/auth-provider-federation-github` package with `createGithubProvider()` and `registerGithubFederation(factory)`.
- `sessionModule({ federationProviderFactory })` option for composition roots that explicitly register federation provider packages.
- `validateRedirect` and `resolveCallbackRedirect` exports from `@o3co/auth-provider-session` for provider package implementations. (`codeChallenge` was already exported since v0.4.0.)
- `@o3co/create-auth-provider` scoped scaffolder package. Replaces the unscoped `create-o3co-auth-provider` so the scaffolder lives under the `@o3co` npm org alongside the runtime packages. Consumers should switch to `npx @o3co/create-auth-provider my-auth-app`. The old `create-o3co-auth-provider` package on npm is deprecated.

### Changed

- **Breaking**: Google and GitHub federation providers are no longer bundled in `@o3co/auth-provider-session`. Consumers must install provider packages, register them with `createFederationProviderFactory()`, and pass the factory to `sessionModule`.
- `templates/standalone` registers `@o3co/auth-provider-federation-google` explicitly for the default Google federation config.
- Scaffolder CLI renamed from `create-o3co-auth-provider` to `@o3co/create-auth-provider` (scoped). The `bin` entry is now `create-auth-provider`.

### Removed

- **Breaking**: `registerBuiltinFederations`, `createGoogleProvider`, and `createGithubProvider` are removed from `@o3co/auth-provider-session`.
- `openid-client` is no longer a runtime dependency of `@o3co/auth-provider-session`; it belongs to the concrete provider packages.
- **Breaking**: `@o3co/auth-provider-did` package. The DID authentication grant is no longer part of this project. The package is no longer maintained here.

### Breaking Changes

- **Config schema is strict; defaults live exclusively in HOCON.**
  `application.schema.mts` no longer carries `.default(X)` for fields
  that hocon already supplies. Operators see the same effective
  defaults at boot — `application.conf` continues to provide them —
  but the schema layer no longer fills in missing values. Two
  concrete operator-facing consequences:
  - **`federations.<name>.enabled` is strict.** Pre-PR the schema-side
    `enabled` carried `.default(false)`, but its composition with
    surrounding `z.preprocess` / `z.optional` was fragile: a bare
    federation entry sometimes parsed as `enabled = false` and
    sometimes caused boot to reject the entry (the trap that
    motivated this refactor). The schema-side default is now
    removed. Each federation entry must declare
    `enabled = true` / `enabled = false` explicitly, or be omitted
    from the config entirely. Bare `federations { google {} }`
    shapes will now fail validation at boot deterministically. If
    you want a federation provider to be active, write
    `enabled = true` in its entry; if you want it inactive, either
    write `enabled = false` or remove the entry.
  - **Library consumers** who construct `AppConfig` from a non-HOCON
    source (TOML, env-only, in-memory object, etc.) must now supply
    every required leaf themselves before calling `validate()` /
    `composeConfigSchema().parse()`. Previously, schema-side
    `.default()` masked missing leaves; that path is gone. See
    `packages/core/docs/adr/2026-04-30-config-schema-strict-defaults-from-hocon.md`
    (consequences I2 / I4) for the rationale and the
    `@o3co/auth-provider-core/testing` subpath for a reference
    fixture baseline. Note that the `testing` factory is intentionally
    a minimal schema-valid baseline rather than a hocon mirror —
    consumers that want the production hocon defaults should load
    `application.conf` directly.
- **`grant_type` wire values (RFC compliance + URN-ification):**
  - `grant_type=authorization` → `grant_type=authorization_code` (RFC 6749 §4.1.3)
  - `grant_type=session` unchanged
- **HOCON config keys + env vars:**
  - `oauth.grants.authorization { ... }` → `oauth.grants.authorization_code { ... }`
  - `OAUTH_GRANTS_AUTHORIZATION_ENABLED` → `OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED`
  - `OAUTH_GRANTS_AUTHORIZATION_PKCE_REQUIRE_S256` → `OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256`
- **Grant policy interface (`GrantPolicyRequest.grantType`):**
  - `/oauth/authorize` flow now passes `"authorization_code"` (was `"authorization"`)
    to `grantPolicy.evaluate()`
  - `refresh_token` path unchanged

**Migration checklist:**

1. Update client requests:
   - `grant_type=authorization` → `authorization_code`
2. Update HOCON config / environment:
   - Rename `oauth.grants.authorization` → `oauth.grants.authorization_code`
   - Rename `OAUTH_GRANTS_AUTHORIZATION_*` → `OAUTH_GRANTS_AUTHORIZATION_CODE_*`
3. If implementing `GrantPolicyHookBase`:
   - Rename `case "authorization":` → `case "authorization_code":` in
     policy dispatch logic

## [0.4.1] - 2026-04-22

### Added

- `create-o3co-auth-provider` CLI scaffolder is now published to npm. Consumers can run `npx create-o3co-auth-provider my-auth-app` to generate a new `auth.provider` project from the standalone template. The package was previously built but held back (`private: true`) from npm publish; this release removes that flag and adds `description` + `repository` metadata.

### Notes

- No changes to `@o3co/auth-provider-core`, `@o3co/auth-provider-session`, `@o3co/auth-provider-oauth`, `@o3co/auth-provider-did`, or `@o3co/auth-provider-foundation`. These packages are re-published at `0.4.1` because the release pipeline bumps all workspace packages in lockstep; their runtime behaviour is identical to `0.4.0`. Consumers upgrading from `0.4.0` → `0.4.1` get an effective no-op reinstall.

## [0.4.0] - 2026-04-22

### Added

- `SupportsLogout` optional capability interface (`EndSessionRequest`, `EndSessionResult`, `SupportsLogout`) and `supportsLogout(provider)` type guard helper in `@o3co/auth-provider-session`. Detects providers whose IdP exposes an OIDC RP-Initiated Logout endpoint. `supportsLogout` accepts `FederationProvider | undefined | null` so it can be called directly on `Map.get(name)` lookups; returns `false` on nullish input. Built-in `google` / `github` providers do not implement this capability.
- `FederationProvider` pure-function interface for upstream OAuth 2 / OIDC identity providers: `buildAuthorizationUrl`, `exchangeCode`, `validateRedirect`, `resolveCallbackRedirect`. Replaces passport-middleware-shaped `setupPassportStrategy` (see Removed).
- `SupportsRefresh` optional capability with `refreshToken(refreshToken): Promise<RefreshedTokens>` and `supportsRefresh(provider)` type guard. `RefreshedTokens = Omit<FederationProfile, "issuer"|"sub"> & { issuer?: string; sub?: string }` reflects that refresh grants legitimately omit identity (Google/GitHub).
- `SupportsClaimMapping` optional capability with `mapClaims(profile): MappedClaims` and `supportsClaimMapping(provider)` type guard.
- `generateCodeVerifier()` / `codeChallenge(verifier)` helpers exported from `@o3co/auth-provider-session` for PKCE S256.
- `registerBuiltinFederations(registry)` one-shot registration + built-in `createGoogleProvider` / `createGithubProvider` (openid-client v6 backed).
- `createClientAuthMiddleware(clientRepository)` exported from `@o3co/auth-provider-oauth` — RFC 6749 §2.3.1 HTTP Basic + form-urlencoded `client_secret_basic` / `client_secret_post` for `/introspect`. Attaches validated `req.oauthClient` (global `Express.Request` namespace augmentation).
- `POST /oauth/federation/:name/token` endpoint (TODO-F-6) — federation token proxy with auto-refresh via `SupportsRefresh` + advisory lock via `SupportsLock`. Returns RFC 6749 §5.1 shape; `expires_in` omitted when upstream issues no finite expiry.
- `FederationTokenStore` optional `SupportsLock.acquireLock()` capability — built-in memory + redis implementations.
- CI vendor-leak guard: `.github/workflows/ci.yml` fails if `arctic|openid-client|oauth4webapi|passport` leaks into any public `.d.mts` / `.d.ts`.
- Per-environment HOCON config overlay for `templates/standalone`: `{ENV}.conf` overrides `application.conf`, with path-containment rejection of traversal env names.
- `KeyStore.sign(options: SignJwtOptions): Promise<string>` for remote-sign support (KMS/HSM).
- `KeyStore.getSigningKidFallback(): string` — cheap signing-kid accessor (fallback for legacy tokens missing `kid` header).
- `JWTPayload` type (RFC 7519, jose-independent) — exported from `@o3co/auth-provider-core` root.
- `SignJwtOptions` type for `sign()` input — exported from `@o3co/auth-provider-core` root.
- `Algorithm` type — promoted to root export.
- `KeyLike` type — promoted to root export.
- `MfaProviderBase` interface + optional `SupportsEnrollment` / `SupportsRevocation` capabilities + `supportsEnrollment()` / `supportsRevocation()` type guards.
- `MfaCoordinator`, `MfaTransactionStore`, `MfaPendingTransaction`, `MfaResumeState` types for MFA flow resume.
- `POST /auth/mfa/verify` route with server-side provider dispatch via `MfaPendingTransaction.providerKind`.
- `MfaProviderFactory = AdapterFactory<MfaProviderBase>` + `createMfaProviderFactory()` + `createMfaRouter()`.
- `AuditEvent` / `AuditSinkBase` interface + `AuditSinkFactory` + `createAuditSinkFactory()` for pluggable audit log sinks.
- Built-in `"console"` audit sink via `registerBuiltinAuditSinks()`.
- `emitAuditEvent(sink, event)` helper — fire-and-forget with error swallow.
- `RateLimitContext` / `RateLimitDecision` / `RateLimiterBase` + `RateLimitSpec` + `RateLimiterFactory` + `createRateLimiterFactory()`.
- Built-in `"memory"` and `"redis"` rate limiters via `registerBuiltinRateLimiters()`.
- `RefreshTokenRotateOutcome` / `RefreshTokenStoreBase` with atomic `rotate()` primitive + `RefreshTokenStoreFactory` + `createRefreshTokenStoreFactory()`.
- `GrantPolicyRequest` / `GrantPolicyContext` / `GrantPolicyDecision` / `GrantPolicyHookBase` + `GrantPolicyHookFactory` + `createGrantPolicyHookFactory()`.
- `family_id` claim added to all `rt+jwt` tokens (always emitted, for future-compatible rotation tracking).
- `grantedScope` / `grantedAudience` fields added to `Code` records (policy-narrowed values persisted at `/oauth/authorize` for later use at `/oauth/token`).

### Changed

- **Breaking**: Federation interface rewritten as a vendor-agnostic pure-function shape. `FederationProviderBase` is renamed back to `FederationProvider` (v0.3.x → interim `FederationProviderBase` → v0.4.0 `FederationProvider`), and the `setupPassportStrategy(passport, ctx)` method is replaced by `buildAuthorizationUrl({ redirectUri, state, codeVerifier })` + `exchangeCode({ code, codeVerifier, redirectUri })`. State (CSRF `state`) and PKCE `codeVerifier` are managed by the session route layer; providers never allocate them.
- **Breaking**: `FederationProfile.id` → `sub` (OIDC claim naming). `FederationProfile.expiresIn: number` → `expiresAt: Date | null` (required). `null` means the upstream provider issues no finite expiry (e.g. GitHub OAuth Apps classic tokens); consumers MUST reuse without refresh. The route layer no longer invents a fallback expiry.
- **Breaking**: `FederationProfile.raw` removed. OIDC-standard claims are first-class fields (`issuer`, `sub`, `email`, `emailVerified`, `name`, `picture`, `accessToken`, `refreshToken`, `idToken`, `expiresAt`). Provider-specific claims (Google `hd`, Microsoft `tid`) are carried by the index signature `[key: string]: unknown`.
- **Breaking**: `FederationProviderFactory` is now `AdapterFactory<FederationProvider>` (was `AdapterFactory<FederationProviderBase>`).
- **Breaking**: `FederationTokens.expiresAt: Date` → `Date | null` (required). Same contract as `FederationProfile.expiresAt`.
- **Breaking**: `UserSessionStore` and `FederationTokenStore` are now **required** at session-module init. Previously optional with a legacy fallback; the module now throws at `init()` time if either is absent from `ModuleContext`.
- **Breaking**: `/login` and `/introspect` error responses follow RFC 6749 §5.2 shape `{ error, error_description }`. Previous `{ message }` shape removed.
- **Breaking**: `createOAuthRouter` drops the `passport` option. Provide `clientRepository` directly; `/introspect` client auth is handled by the new built-in `createClientAuthMiddleware`.
- **Breaking**: `KeyStore.getVerificationKey(kid)` is now `Promise<KeyLike>` (was sync). Callers must `await`.
- **Breaking**: `KeyStore.getVerificationKeys()` is now `Promise<ManagedKey[]>` (was sync). Callers must `await`.
- `AppOptions` now accepts optional `mfaProviderFactory`, `mfaCoordinator`, `mfaTransactionStore`, `auditSink`, `rateLimiter`, `refreshTokenStore`, `grantPolicy`. `mfaCoordinator` setting requires both `mfaProviderFactory` and `mfaTransactionStore`; core throws at startup on misconfiguration.
- `refreshToken.mts` calls `refreshTokenStore.rotate()` atomically when a store is configured; otherwise unchanged (stateless fallback preserved).
- `/oauth/authorize` runs `grantPolicy.evaluate()` once at code issuance and persists narrowed values on the Code record. `/oauth/token` (authorization_code) honors persisted values without re-evaluating. Other grants evaluate at the token endpoint.
- `/oauth/token`, `/oauth/introspect`, `/oauth/authorize` now consult optional `rateLimiter` (returning 429 + `Retry-After` on denial) and emit audit events to the optional `auditSink` for success/failure transitions.

### Removed

- **Breaking**: `passport`, `passport-local`, `passport-google-oauth20`, `passport-github2`, `passport-oauth2`, `passport-oauth2-client-password`, `passport-http`, and all `@types/passport*` are removed as direct runtime dependencies from `@o3co/auth-provider-session`, `@o3co/auth-provider-oauth`, and `templates/standalone`. Built-in Google/GitHub providers are re-implemented on top of `openid-client` v6 (panva, OpenID Foundation Certified RP); vendor types stay inside each adapter and do not leak into the public `.d.mts` surface.
- **Breaking**: `createPassport()`, `SetupPassportContext`, and the `_createPassport` internal hook removed from `@o3co/auth-provider-session`. State (CSRF) and PKCE are managed by the route layer; providers are pure functions.
- **Breaking**: `VerifyUserContext` deprecated type alias in `@o3co/auth-provider-session`. The underlying `setupPassportStrategy(passport, ctx)` method is removed along with its context type.
- **Breaking**: `KeyStore.getSigningKey()`. Use `sign(options)` instead.
- **Breaking**: `KeyStore.current`. Use `getSigningKidFallback()` (kid only; private key is no longer exposed).
- **Breaking**: `KeyStore.previous`. Use `await getVerificationKeys()` (current + active previous unified).
- **Breaking**: `@o3co/auth-provider-oauth` no longer depends on `express-rate-limit`. The legacy `tokenRateLimit` / `authorizeRateLimit` middleware is removed from `createOAuthRouter`, along with the `config.rateLimit.{token,authorize}` schema fields. Consumers previously relying on the built-in middleware must configure `AppOptions.rateLimiter` with a `RateLimiterBase` adapter (built-in `"memory"` or `"redis"` available via `createRateLimiterFactory()` + `registerBuiltinRateLimiters()`).

### Migration

See `packages/session/README.md` and `packages/oauth/README.md` for full v0.3.x → v0.4.0 migration guide with before/after code samples.

#### Federation interface

```ts
// Before (v0.3.x)
const provider: FederationProviderBase = {
  setupPassportStrategy(passport, ctx) {
    passport.use(new GoogleStrategy({ /* ... */ }, ctx.verify));
  },
};

// After (v0.4.0)
const provider: FederationProvider = {
  name: "google",
  scope: ["openid", "email", "profile"],
  buildAuthorizationUrl({ redirectUri, state, codeVerifier }) {
    /* return URL */
  },
  async exchangeCode({ code, codeVerifier, redirectUri }) {
    /* return FederationProfile with expiresAt: Date | null */
  },
  validateRedirect(url) { /* ... */ },
  resolveCallbackRedirect(session) { /* ... */ },
};
```

#### `FederationProfile.expiresAt`

```ts
// Before: optional, route invented a 1h fallback when missing
const profile: FederationProfile = { /* expiresAt?: Date */ };

// After: required, null when provider issues no finite expiry (GitHub OAuth Apps classic)
const profile: FederationProfile = {
  issuer, sub, accessToken,
  expiresAt: expiresIn !== undefined
    ? new Date(Date.now() + expiresIn * 1000)
    : null,
};
```

#### Error response shape

```ts
// Before (/login, /introspect): { message: "..." }
// After: RFC 6749 §5.2 { error, error_description }
{ "error": "invalid_credentials", "error_description": "Incorrect username or password." }
```

#### Module wiring

`UserSessionStore` and `FederationTokenStore` are now required at session module init. Configure them in `AppOptions` before calling `createApp`. Core provides built-in memory + redis adapters via `createUserSessionStoreFactory()` and `createFederationTokenStoreFactory()`.

### KeyStore migration

JWT signing:

```ts
// Before
const { kid, privateKey } = keyStore.getSigningKey();
const token = await new SignJWT(claims)
  .setProtectedHeader({ alg: keyStore.algorithm, kid })
  .sign(privateKey);

// After
const token = await keyStore.sign({ claims });
```

Verification callers must now `await` `getVerificationKey(kid)` / `getVerificationKeys()`. Replace `keyStore.current.kid` with `keyStore.getSigningKidFallback()`.
