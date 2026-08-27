# Changelog — @o3co/auth-provider-dpop

All notable changes to this package will be documented in this file.

## [Unreleased]

### BREAKING — the expected `htu` comes from the configured issuer (#292)

- **`createDPoPMechanism` takes a required `issuer` option**, and the URL a
  proof's `htu` is checked against is now that issuer's **origin** plus the
  path the request reached (`req.originalUrl`). It used to be reconstructed
  from `req.protocol` and the `Host` header — both of which read
  `X-Forwarded-Proto` / `X-Forwarded-Host` whenever Express `trust proxy` is
  on. A caller who could reach the AS past the edge therefore chose the value
  its own proof had to match, holding both halves of the comparison and
  reducing the `htu` binding to a formality.

  The issuer is a property of the deployment and no request can move it, which
  is why it is the right source — the same reasoning that stopped `iss` being
  derived from `Host` in #266/#307. A path prefix on the issuer is ignored: the
  path belongs to the request, which already carries whatever prefix the AS is
  mounted under.

  The option is validated as a canonical issuer URL at construction rather than
  at first use. A mechanism that cannot name its own origin would otherwise
  fail every proof with `htu_mismatch`, which reads as a client bug rather than
  a misconfiguration.

- **`dpopModule` now reads `config.oauth.jwt.issuer`** and refuses to build a
  mechanism without it. Core's `CoreConfigSchema` has required that key since
  #266/#307, so this is not a second place to configure an origin.

- **`http.trustProxy` is no longer load-bearing for DPoP.** The README's
  operator requirement to set it "or every request fails `htu_mismatch`" is
  gone. It still matters for IP-keyed rate limiting and the session CSRF origin
  check.

  **Migration:** check that `oauth.jwt.issuer` names the origin clients
  actually reach. If it names an internal hostname while clients connect to a
  public one, proofs that verified before stop verifying — correctly, because
  the AS was previously agreeing to whatever origin the request asserted. The
  fix is the issuer, not the proof.


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
