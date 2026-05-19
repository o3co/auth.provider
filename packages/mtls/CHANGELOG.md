# Changelog — @o3co/auth-provider-mtls

All notable changes to this package will be documented in this file.

## [Unreleased]

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
