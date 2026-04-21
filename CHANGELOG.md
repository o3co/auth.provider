# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- `SupportsLogout` optional capability interface (`EndSessionRequest`, `EndSessionResult`, `SupportsLogout`) and `supportsLogout(provider)` type guard helper in `@o3co/auth-provider-session`. Detects providers whose IdP exposes an OIDC RP-Initiated Logout endpoint. `supportsLogout` accepts `FederationProviderBase | undefined | null` so it can be called directly on `Map.get(name)` lookups; returns `false` on nullish input. Built-in `google` / `github` providers do not implement this capability.
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

- **Breaking**: `FederationProvider` interface renamed to `FederationProviderBase` in `@o3co/auth-provider-session`. Consumers must update type imports. No runtime or behavioral change.
- **Breaking**: `FederationProviderFactory` is now `AdapterFactory<FederationProviderBase>` (was `AdapterFactory<FederationProvider>`). The `createFederationProviderFactory()` function signature is unchanged; only the element type name differs.
- **Breaking**: `KeyStore.getVerificationKey(kid)` is now `Promise<KeyLike>` (was sync). Callers must `await`.
- **Breaking**: `KeyStore.getVerificationKeys()` is now `Promise<ManagedKey[]>` (was sync). Callers must `await`.
- `AppOptions` now accepts optional `mfaProviderFactory`, `mfaCoordinator`, `mfaTransactionStore`, `auditSink`, `rateLimiter`, `refreshTokenStore`, `grantPolicy`. `mfaCoordinator` setting requires both `mfaProviderFactory` and `mfaTransactionStore`; core throws at startup on misconfiguration.
- `refreshToken.mts` calls `refreshTokenStore.rotate()` atomically when a store is configured; otherwise unchanged (stateless fallback preserved).
- `/oauth/authorize` runs `grantPolicy.evaluate()` once at code issuance and persists narrowed values on the Code record. `/oauth/token` (authorization_code) honors persisted values without re-evaluating. Other grants evaluate at the token endpoint.
- `/oauth/token`, `/oauth/introspect`, `/oauth/authorize` now consult optional `rateLimiter` (returning 429 + `Retry-After` on denial) and emit audit events to the optional `auditSink` for success/failure transitions.

### Removed

- **Breaking**: `VerifyUserContext` deprecated type alias in `@o3co/auth-provider-session`. Use `SetupPassportContext` (introduced in the Federation factory PR #64).
- **Breaking**: `KeyStore.getSigningKey()`. Use `sign(options)` instead.
- **Breaking**: `KeyStore.current`. Use `getSigningKidFallback()` (kid only; private key is no longer exposed).
- **Breaking**: `KeyStore.previous`. Use `await getVerificationKeys()` (current + active previous unified).
- **Breaking**: `@o3co/auth-provider-oauth` no longer depends on `express-rate-limit`. The legacy `tokenRateLimit` / `authorizeRateLimit` middleware is removed from `createOAuthRouter`, along with the `config.rateLimit.{token,authorize}` schema fields. Consumers previously relying on the built-in middleware must configure `AppOptions.rateLimiter` with a `RateLimiterBase` adapter (built-in `"memory"` or `"redis"` available via `createRateLimiterFactory()` + `registerBuiltinRateLimiters()`).

### Migration

Replace `FederationProvider` with `FederationProviderBase` and `VerifyUserContext` with `SetupPassportContext` at every type import site. No runtime or config change is required.

```ts
// Before
import type { FederationProvider, VerifyUserContext } from "@o3co/auth-provider-session";

// After
import type { FederationProviderBase, SetupPassportContext } from "@o3co/auth-provider-session";
```

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
