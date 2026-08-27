# Changelog — @o3co/auth-provider-core

All notable changes to this package will be documented in this file.

## [Unreleased]

### BREAKING — `http.trustProxy` takes a CIDR / hop policy (#292)

- **`http.trustProxy` widened from `boolean` to `boolean | number | string[]`**,
  matching Express's own `trust proxy` vocabulary: `false`, `true`, a hop count,
  or a list of IP literals / CIDR ranges / named ranges (`loopback`,
  `linklocal`, `uniquelocal`). `false` and `true` are unchanged, so no existing
  config has to move; the list is what lets a deployment say *which* hop may
  rewrite `req.ip` rather than trusting a forwarded address from anyone able to
  reach the process.

  Because HOCON substitutes `${?HTTP_TRUST_PROXY}` as a scalar string, the
  schema coerces: `"true"` / `"false"` to booleans, a bare integer to a hop
  count, an empty value to `false` (fail closed), and anything else to a
  comma-separated address list. Without that the only documented override
  surface could not express a list.

  Entries are validated at boot with the issue path naming the offending index.
  A hostname, a typo'd keyword, an out-of-range prefix length, or dotted-netmask
  notation fails loudly rather than becoming a rule that never matches — the
  silent version surfaces as every user sharing one rate-limit bucket.

### Added

- **`src/net/trusted-proxy.mts` — the single trusted-proxy address vocabulary**
  (#292), exported as `checkTrustedProxyEntry`, `isTrustedProxyEntry`,
  `describeTrustedProxyEntryRejection`, `createTrustedProxyMatcher`,
  `TRUSTED_PROXY_NAMED_RANGES`, and the `TrustedProxyEntryRejection` /
  `TrustedProxyMatcherOptions` types. `checkTrustedProxyEntry` /
  `describeTrustedProxyEntryRejection` mirror the `checkCanonicalIssuer` pair:
  a reason for a Zod `superRefine`, a sentence for a `throw` site.

  `@o3co/auth-provider-mtls` held a private copy of the matcher for
  `oauth.mtls.trusted-proxies` (#280) and now consumes this one, so the two
  keys cannot drift into different dialects. The matcher is built on
  `node:net.BlockList` and is always fed `req.socket.remoteAddress`, never
  `req.ip` — authenticating a forwarding hop with a header `X-Forwarded-For`
  rewrites would prove nothing.


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
- See ADR `packages/core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md`
  for the cross-mechanism design rationale.

### Notes

- The existing `grantMiddleware` contribution kind remains supported for
  general per-route middleware. Token-binding mechanism modules (DPoP,
  mTLS, future) SHOULD use `tokenBindingMechanisms` so the unified
  `DispatchPolicy` applies; using `grantMiddleware` for that purpose
  bypasses cross-module arbitration and is discouraged.
- No public API removed. Wire protocol unchanged.
