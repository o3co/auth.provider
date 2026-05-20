# Changelog — @o3co/auth-provider-oauth

All notable changes to this package will be documented in this file.

## [Unreleased]

### Added (Wave 2 Phase 4 — 2026-05-20)

- **End-to-end integration test** `tokenBinding.introspect.integration.test.mts`
  pairing the issuance side (Phase 2 DPoP, Phase 3 mTLS) with the
  introspection side (Phase 1 typed `IntrospectResponse`). Three
  cases: DPoP-bound AT introspects with `cnf.jkt` + `token_type:
  "DPoP"`; mTLS-bound AT with `cnf.x5t#S256` + `token_type: "Bearer"`;
  plain AT with no `cnf` + `token_type: "Bearer"`. First test that
  exercises both code paths on the same token.
- **README section "Token-binding cnf flow (Wave 2)"** documents AT
  cnf mechanism-agnostic propagation, RT cnf public-client gate, the
  §9.2 5-row matrix per mechanism, mechanism-boundary regression,
  compound-`cnf` pre-matrix reject, and the introspect echo.

### Added (Wave 2 Phase 3 Sub-PR 3c — 2026-05-20)

- **Gate widened** in `authorization.mts` and `refreshToken.mts` from
  `bindingIsDpop && isPublicClient` to `(bindingIsDpop ||
  bindingIsMtls) && isPublicClient`. Mechanism allowlist preserved
  structurally (the PR #185 / Codex Important #2 boundary survives
  the widen).
- **mTLS refresh-time matrix (§9.2 mTLS rows)** in `refreshToken.mts`,
  parallel to the existing DPoP matrix. Five rows + distinct
  errorDescription strings for cert-absent vs thumbprint-mismatch
  rejections so SIEMs can distinguish "stolen RT replayed without
  cert" from "mid-rotation / multi-cert attack".
- **Compound-`cnf` pre-matrix reject** (Codex Critical #2): an RT
  carrying BOTH `cnf.jkt` AND `cnf.x5t#S256` is rejected with
  `invalid_grant` BEFORE either matrix runs. Closes the ambiguity
  around multi-mechanism binding semantics at runtime; Phase 1's
  narrow `Confirmation` union is the TypeScript-layer twin defense.
- **Mechanism-boundary regression**: `proofX5t` extraction gates on
  `kind === "mtls"`, symmetric to the PR #185 DPoP rule. A non-mTLS
  mechanism emitting an `{ "x5t#S256": "..." }` confirmation cannot
  satisfy an mTLS-bound RT.
- **Phase 2 deferral pin tests inverted**: the two tests at PR #185
  that asserted "mTLS public-client RT stays plain (deferred)" now
  assert RT bound with `x5t#S256`. Docstrings + titles rewritten to
  cite RFC 8705 §4 SHOULD as positive authority.
- **New integration tests:**
  - `mtls.clientCredentials.integration.test.mts` — AT cnf
    propagation + no RT (RFC 6749 §4.4.3 pinned).
  - `mtls.authorizationCode.integration.test.mts` — public + confidential
    client paths.
  - `mtls.refreshToken.integration.test.mts` — full 5-row matrix +
    compound-cnf reject + mechanism boundary.
  - `tokenBinding.dispatchPolicy.integration.test.mts` — grant-visible
    side of the cross-mechanism dispatch contract.

### Added (Wave 2 Phase 2 — 2026-04 → 2026-05-13)

- DPoP `cnf.jkt` claim emission in `authorization.mts` and
  `refreshToken.mts` for public clients (RFC 9449 §5).
- 5-row refresh-time DPoP matrix in `refreshToken.mts` (Codex Round
  1 Important #1) — pre-empts the mTLS matrix structure.
- Mechanism boundary rule (Codex Important #2): `proofJkt`
  extraction gates on `kind === "dpop"`.

### Notes

- See [ADR 2026-05-20-token-binding-first-class-abstraction.md](../core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md)
  for the cross-cutting Wave 2 design rationale spanning core +
  dpop + mtls + oauth.
- Wire protocol unchanged. No public API removed.
