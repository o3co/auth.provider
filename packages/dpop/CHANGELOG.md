# Changelog — @o3co/auth-provider-dpop

All notable changes to this package will be documented in this file.

## [Unreleased]

### Changed (Cross-mechanism dispatch refactor — 2026-05-19)

- **Contribution shape migrated** from `grantMiddleware` to the new
  `tokenBindingMechanisms` slot (declared by `@o3co/auth-provider-core`).
  `dpopModule` now contributes the raw `TokenBindingMechanism` and core
  composes ONE `tokenBindingMw` from all installed binding-mechanism
  modules so the configured `DispatchPolicy` arbitrates cross-module.
  See `.claude/superpowers/specs/2026-05-19-wave-2-cross-mechanism-dispatch-refactor-spec.md`.
- **Removed `oauth.tokenBinding` declarations** from `dpopConfigSchema`
  and `reference.conf`. The `oauth.tokenBinding.dispatch-policy` key is
  now owned by core's bundled config schema (single source of truth
  across DPoP, mTLS, and future binding-mechanism modules). Operators
  who set the key in their `application.conf` are unaffected; operators
  who relied on dpop's reference.conf default still get
  `"intent-explicit"` via core's reference.conf default.
- The DPoP mechanism itself (`createDPoPMechanism`, replay store, htu
  normalization, RFC 9449 §6 validation sequence) is unchanged.
