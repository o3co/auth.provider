# Changelog — @o3co/auth-provider-core

All notable changes to this package will be documented in this file.

## [Unreleased]

### Added (Wave 2 Phase 4 — 2026-05-20)

- **ADR `2026-05-20-token-binding-first-class-abstraction.md`** at
  `packages/core/docs/adr/` documents the Wave 2 design rationale:
  why `TokenBindingMechanism` is a first-class extension surface,
  what the `Confirmation` union narrowness buys, why grant-side
  mechanism allowlist is preferred over `confirmation !== undefined`,
  and why the cross-mechanism refactor was inserted mid-flight after
  Sub-PR 3b review.
- **README section "Token-binding mechanisms (Wave 2)"** added to
  `packages/core/README.md` documenting `TokenBinding`, `Confirmation`,
  `TokenBindingMechanism`, `TokenBindingMechanismFactory`, the
  built-in mechanism packages, and `oauth.tokenBinding.dispatch-policy`
  semantics.

### Added (Cross-mechanism dispatch refactor — 2026-05-19)

- **New `tokenBindingMechanisms` contribution kind.** Modules ship a
  `TokenBindingMechanismFactory<Deps>` returning a raw
  `TokenBindingMechanism | null`; core's `assembleApp` collects all
  contributions, filters null returns, and composes ONE `tokenBindingMw`
  mounted on `/oauth/token` BEFORE the existing `grantMiddleware` mount
  loop. The configured `DispatchPolicy`
  (`oauth.tokenBinding.dispatch-policy`) arbitrates across mechanism
  modules — `intent-explicit` (default) prefers explicit-intent
  mechanisms (DPoP) over ambient (mTLS); `strict-mutual-exclusion`
  rejects requests where ≥2 mechanisms succeed.
- **New exported type `TokenBindingMechanismFactory<Deps>`** from
  `@o3co/auth-provider-core/modules/manifest` (re-exported from the
  package root).
- **New `oauth.tokenBinding.dispatch-policy` config key** in
  `CoreConfigSchema` (single source of truth across all installed
  binding-mechanism modules — DPoP, mTLS, future). Synthesized middleware
  reads this with a defensive fallback to `"intent-explicit"`. The
  default also ships in `packages/core/config/reference.conf` with the
  `OAUTH_TOKEN_BINDING_DISPATCH_POLICY` env-var override hook.
- Per cross-mechanism dispatch refactor spec at
  `.claude/superpowers/specs/2026-05-19-wave-2-cross-mechanism-dispatch-refactor-spec.md`.

### Notes

- The existing `grantMiddleware` contribution kind remains supported for
  general per-route middleware. Token-binding mechanism modules (DPoP,
  mTLS, future) SHOULD use `tokenBindingMechanisms` so the unified
  `DispatchPolicy` applies; using `grantMiddleware` for that purpose
  bypasses cross-module arbitration and is discouraged.
- No public API removed. Wire protocol unchanged.
