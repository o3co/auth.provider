# @o3co/auth-provider-mtls

mTLS (RFC 8705) sender-constrained access token support for `@o3co/auth-provider`.

> **Status:** Phase 3 in progress. Sub-PR 3a ships the package skeleton + dialect parsers + thumbprint + cert type. The mechanism factory, module wiring, and grant integration land in Sub-PR 3b / 3c. The package is NOT yet usable end-to-end.

## Overview

Sender-constrained access tokens per [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) §3 (Mutual TLS Client Certificate-Bound Access Tokens). The mechanism extracts the client cert presented during the TLS handshake (or forwarded by a reverse proxy), computes the SHA-256 thumbprint of the DER encoding, and emits it as the `cnf.x5t#S256` claim on the issued access token.

Implements:

- RFC 8705 §3 — AT binding (Sub-PR 3a + 3b).
- RFC 8705 §3.1 — `x5t#S256` thumbprint algorithm (Sub-PR 3a).
- RFC 8705 §4 — public-client RT binding SHOULD (Sub-PR 3c).

The package plugs into the existing `tokenBindingMw` from `@o3co/auth-provider-core` (Phase 1b) and emits a `TokenBinding` with `kind: "mtls"`.

Further documentation (Trusted-Proxy Security Guidance, PKI Mode Scope, sample proxy configs) lands with Sub-PR 3b.
