# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- `SupportsLogout` optional capability interface (`EndSessionRequest`, `EndSessionResult`, `SupportsLogout`) and `supportsLogout(provider)` type guard helper in `@o3co/auth-provider-session`. Detects providers whose IdP exposes an OIDC RP-Initiated Logout endpoint. `supportsLogout` accepts `FederationProviderBase | undefined | null` so it can be called directly on `Map.get(name)` lookups; returns `false` on nullish input. Built-in `google` / `github` providers do not implement this capability.
- `KeyStore.sign(options: SignJwtOptions): Promise<string>` for remote-sign support (KMS/HSM).
- `KeyStore.getCurrentKid(): string` — cheap signing-kid accessor (fallback for legacy tokens missing `kid` header).
- `JWTPayload` type (RFC 7519, jose-independent) — exported from `@o3co/auth-provider-core` root.
- `SignJwtOptions` type for `sign()` input — exported from `@o3co/auth-provider-core` root.
- `Algorithm` type — promoted to root export.
- `KeyLike` type — promoted to root export.

### Changed

- **Breaking**: `FederationProvider` interface renamed to `FederationProviderBase` in `@o3co/auth-provider-session`. Consumers must update type imports. No runtime or behavioral change.
- **Breaking**: `FederationProviderFactory` is now `AdapterFactory<FederationProviderBase>` (was `AdapterFactory<FederationProvider>`). The `createFederationProviderFactory()` function signature is unchanged; only the element type name differs.
- **Breaking**: `KeyStore.getVerificationKey(kid)` is now `Promise<KeyLike>` (was sync). Callers must `await`.
- **Breaking**: `KeyStore.getVerificationKeys()` is now `Promise<ManagedKey[]>` (was sync). Callers must `await`.

### Removed

- **Breaking**: `VerifyUserContext` deprecated type alias in `@o3co/auth-provider-session`. Use `SetupPassportContext` (introduced in the Federation factory PR #64).
- **Breaking**: `KeyStore.getSigningKey()`. Use `sign(options)` instead.
- **Breaking**: `KeyStore.current`. Use `getCurrentKid()` (kid only; private key is no longer exposed).
- **Breaking**: `KeyStore.previous`. Use `await getVerificationKeys()` (current + active previous unified).

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

Verification callers must now `await` `getVerificationKey(kid)` / `getVerificationKeys()`. Replace `keyStore.current.kid` with `keyStore.getCurrentKid()`.
