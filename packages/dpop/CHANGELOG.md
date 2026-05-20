# Changelog — @o3co/auth-provider-dpop

All notable changes to this package will be documented in this file.

## [Unreleased]

### Changed (Wave 2 Phase 4 — 2026-05-20)

- **README quick-start filled in** with the composition-root snippet,
  the `application.conf` opt-in block, and a "Cross-mechanism
  dispatch (DPoP + mTLS)" section pointing at the symmetric mTLS-side
  documentation. The pre-Phase-4 placeholder "(Filled in by Sub-PR
  2b/2c)" is removed.
- See [ADR 2026-05-20-token-binding-first-class-abstraction.md](../core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md)
  for the cross-cutting Wave 2 design rationale.

### Changed (Cross-mechanism dispatch refactor — 2026-05-19)

- **Contribution shape migrated** from `grantMiddleware` to the new
  `tokenBindingMechanisms` slot (declared by `@o3co/auth-provider-core`).
  `dpopModule` now contributes the raw `TokenBindingMechanism` and core
  composes ONE `tokenBindingMw` from all installed binding-mechanism
  modules so the configured `DispatchPolicy` arbitrates cross-module.
  See ADR `packages/core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md`
  for the design rationale.
- **Removed `oauth.tokenBinding` declarations** from `dpopConfigSchema`
  and `reference.conf`. The `oauth.tokenBinding.dispatch-policy` key is
  now owned by core's bundled config schema (single source of truth
  across DPoP, mTLS, and future binding-mechanism modules). Operators
  who set the key in their `application.conf` are unaffected; operators
  who relied on dpop's reference.conf default still get
  `"intent-explicit"` via core's reference.conf default.
- The DPoP mechanism itself (`createDPoPMechanism`, replay store, htu
  normalization, RFC 9449 §6 validation sequence) is unchanged.
