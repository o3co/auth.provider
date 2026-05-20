# Changelog — @o3co/auth-provider-mtls

All notable changes to this package will be documented in this file.

## [Unreleased]

### Changed (Wave 2 Phase 4 — 2026-05-20)

- **README status line updated** to reflect Phase 3 completion — the
  Phase 3 Sub-PR 3c grant-side `cnf.x5t#S256` emission + §9.2
  refresh-time matrix + compound-`cnf` reject + mechanism-boundary
  regression are all shipped. The earlier "lands in Sub-PR 3c" hedge
  is removed.
- See [ADR 2026-05-20-token-binding-first-class-abstraction.md](../core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md)
  for the cross-cutting Wave 2 design rationale.

### Added (Phase 3 Sub-PR 3c — 2026-05-20)

- **mTLS refresh-token binding is now enforced end-to-end.** The gate
  in `@o3co/auth-provider-oauth` grants (`authorization.mts` and
  `refreshToken.mts`) was widened from `bindingIsDpop && isPublicClient`
  to `(bindingIsDpop || bindingIsMtls) && isPublicClient`. Public clients
  presenting an mTLS certificate for token binding now receive both an
  AT carrying `cnf.x5t#S256` AND an RT carrying `cnf.x5t#S256` (RFC
  8705 §4 SHOULD). Note: this is RFC 8705 §3-§4 sender-constrained
  *token binding*, not the RFC 8705 §2 mTLS *client authentication*
  flow (which remains out of scope).
- **mTLS refresh-time matrix (§9.2 mTLS rows)** added in
  `refreshToken.mts`, parallel to the existing DPoP matrix. Five rows
  enforce that an RT promising mTLS binding is only honored when the
  presented client certificate's `x5t#S256` matches the persisted
  binding. Row 3 (cert absent) and row 4 (thumbprint mismatch) reject
  with `invalid_grant` and distinct error descriptions so SIEMs can
  distinguish "RT replayed without cert" from "mid-rotation /
  multi-cert attack". Confidential clients continue to issue plain
  RTs (mirroring the DPoP public-client gate per RFC 9449 §5 reasoning,
  generalized to mTLS).
- **Compound-cnf rejection** — an RT carrying BOTH `cnf.jkt` AND
  `cnf.x5t#S256` is rejected with `invalid_grant` BEFORE either matrix
  runs. Stage 1 only supports single-mechanism bindings; a compound
  cnf could only arise from a bug or attacker-crafted RT. The reject
  closes the ambiguity structurally (Codex Critical #2 from the
  Phase 3 §11.4 review chain).
- **Mechanism-boundary regression**: a non-mTLS-emitting mechanism that
  hypothetically presents an `{ "x5t#S256": "..." }` confirmation
  cannot satisfy an mTLS-bound RT — the `proofX5t` extraction gates on
  `kind === "mtls"`. Symmetric to the PR #185 DPoP boundary rule.
- The Phase 2 deferral pin tests in
  `dpop.authorizationCode.integration.test.mts` and
  `dpop.refreshToken.integration.test.mts` are inverted: mTLS public
  clients are now asserted to receive bound RTs (was: asserted RT
  plain). The RT-binding emission and the refresh-time matrix land
  atomically — there is no release window where a bound RT could be
  refreshed without a cert.

### Changed (Cross-mechanism dispatch refactor — 2026-05-19)

- **Contribution shape migrated** from `grantMiddleware` to the new
  `tokenBindingMechanisms` slot (declared by `@o3co/auth-provider-core`).
  `mtlsModule` now contributes the raw `TokenBindingMechanism` and core
  composes ONE `tokenBindingMw` from all installed binding-mechanism
  modules so the configured `DispatchPolicy` arbitrates cross-module.
  Resolves the §11.4 known limitation documented at Sub-PR 3b merge.
  See `.claude/superpowers/specs/2026-05-19-wave-2-cross-mechanism-dispatch-refactor-spec.md`.
- **Removed `oauth.tokenBinding` declarations** from `mtlsConfigSchema`
  and `reference.conf`. The `oauth.tokenBinding.dispatch-policy` key is
  now owned by core's bundled config schema (single source of truth
  across DPoP, mTLS, and future binding-mechanism modules).
- **README**: "Known Limitations" section replaced with "Cross-mechanism
  dispatch (DPoP + mTLS)" describing the unified DispatchPolicy
  behavior. Composition root example updated to enable both modules.
- The mTLS extractor + PKI chain validation themselves
  (`createMtlsMechanism`, `validateCertChain`) are unchanged.

### Security (Phase 3 Sub-PR 3b — Copilot Critical regression)

- **`validateCertChain` now requires explicit cryptographic signature verification at every hop.** Previously the chain walk used only `X509Certificate.checkIssued()` which performs DN / AKID / SKID / CA-bit matching but does NOT verify the signature (OpenSSL `X509_check_issued` documents this). An attacker omitting or crafting the AKID extension could forge a leaf with matching issuer DN and pass our chain validation without proving cryptographic relation to the trust anchor. Each hop now pairs `checkIssued` with `X509Certificate.verify(issuer.publicKey)`. Distinct audit reasons (`"trust anchor matched by DN but signature verification failed"` / `"intermediate matched by DN but signature verification failed"`) make the attack signal visible. Pinned by a new regression test using a committed attacker-leaf.pem fixture (same DN as the legit root, signed by a different key).

### Added (Phase 3 Sub-PR 3b)

- `createMtlsMechanism(options)` factory — returns a `TokenBindingMechanism` with `kind: "mtls"` + `intentExplicit: false`. Implements the 7-step extract sequence per spec §6: source resolve (header / tls-layer) → dialect parse → PEM↔DER → validity window → PKI chain → thumbprint → `cnf.x5t#S256`.
- `MtlsMechanismOptions` shape: `source` (header / tls-layer), `certHeader`, `certHeaderDialect`, `mode` (self-signed / pki), `trustedCas`, `logger`.
- `mtlsModule` — declarative manifest contributing `grantMiddleware`. Returns null when `oauth.mtls.enabled === false` (the secure default).
- `mtlsConfigSchema` — Zod schema for `oauth.mtls` + shared `oauth.tokenBinding`.
- `validateCertChain` — narrow-mode PKI chain validation (internal; not exported). Walks chain with cycle detection via `fingerprint256`, per-hop validity, defense-in-depth `basicConstraints.CA` check.
- `reference.conf` — secure-default-opt-in (`enabled = false`, `mode = "self-signed"`, `source = "header"`, dialect `"envoy"`).
- Boot-time fail-loud invariants (spec §11.2): rejects `mode = "pki"` with empty `trusted-cas` AND rejects `mode = "pki"` with `source = "tls-layer"`. Enforced at both `mtlsModule` and `createMtlsMechanism` layers as defense-in-depth.
- `trusted-cas` entries support both literal PEM and `file:<path>` (synchronous read at boot).
- README: "Trusted-Proxy Security Guidance" (RFC 8705 §6.5), "PKI Mode Scope" (§7.2/§7.3 honest scope-out), "Trusted-CA entries" form documentation, and "Known Limitations" section.

### Known Limitations (Phase 3)

- **Single binding mechanism per deployment.** When both `dpopModule` and `mtlsModule` are enabled, each contributes its own independent `tokenBindingMw`; `dispatch-policy` cannot arbitrate across module boundaries and the second mechanism's binding silently overwrites the first. Enable one mechanism per AS until a follow-up sub-PR refactors the contribution surface. See README "Known Limitations" + spec §11.4.

Implements the Phase 3 spec at `.claude/superpowers/specs/2026-05-18-wave-2-phase-3-mtls-spec.md` §13 T3b.

### Added (Phase 3 Sub-PR 3a)

- Initial `@o3co/auth-provider-mtls` package skeleton.
- `pemToDer` + `derToPem` codec helpers (internal).
- `parseEnvoyXfccHeader` + `parsePlainPemHeader` dialect parsers (internal).
- `computeCertThumbprint` (RFC 8705 §3.1 — base64url-encoded SHA-256 hash of DER, trailing `=` padding stripped).
- `ClientCertificate` type + `parseDerToCertificate`.
- `MtlsError` + `MtlsReasonCode` union.

Implements the Phase 3 spec at `.claude/superpowers/specs/2026-05-18-wave-2-phase-3-mtls-spec.md` §13 T3a.
