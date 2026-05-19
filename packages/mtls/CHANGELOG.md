# Changelog — @o3co/auth-provider-mtls

All notable changes to this package will be documented in this file.

## [Unreleased]

### Added (Phase 3 Sub-PR 3a)

- Initial `@o3co/auth-provider-mtls` package skeleton.
- `pemToDer` + `derToPem` codec helpers (internal).
- `parseEnvoyXfccHeader` + `parsePlainPemHeader` dialect parsers (internal).
- `computeCertThumbprint` (RFC 8705 §3.1 — base64url-encoded SHA-256 hash of DER, trailing `=` padding stripped).
- `ClientCertificate` type + `parseDerToCertificate`.
- `MtlsError` + `MtlsReasonCode` union.

Implements the Phase 3 spec at `.claude/superpowers/specs/2026-05-18-wave-2-phase-3-mtls-spec.md` §13 T3a.
