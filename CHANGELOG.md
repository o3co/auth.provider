# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- `SupportsLogout` optional capability interface (`EndSessionRequest`, `EndSessionResult`, `SupportsLogout`) and `supportsLogout(provider)` type guard helper in `@o3co/auth-provider-session`. Detects providers whose IdP exposes an OIDC RP-Initiated Logout endpoint. Built-in `google` / `github` providers do not implement this capability.

### Changed

- **Breaking**: `FederationProvider` interface renamed to `FederationProviderBase` in `@o3co/auth-provider-session`. Consumers must update type imports. No runtime or behavioral change.
- **Breaking**: `FederationProviderFactory` is now `AdapterFactory<FederationProviderBase>` (was `AdapterFactory<FederationProvider>`). The `createFederationProviderFactory()` function signature is unchanged; only the element type name differs.

### Removed

- **Breaking**: `VerifyUserContext` deprecated type alias in `@o3co/auth-provider-session`. Use `SetupPassportContext` (introduced in the Federation factory PR #64).

### Migration

Replace `FederationProvider` with `FederationProviderBase` and `VerifyUserContext` with `SetupPassportContext` at every type import site. No runtime or config change is required.

```ts
// Before
import type { FederationProvider, VerifyUserContext } from "@o3co/auth-provider-session";

// After
import type { FederationProviderBase, SetupPassportContext } from "@o3co/auth-provider-session";
```
