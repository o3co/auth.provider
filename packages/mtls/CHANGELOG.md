# Changelog — @o3co/auth-provider-mtls

All notable changes to this package will be documented in this file.

## [Unreleased]

### Added — `trusted-proxies` accepts CIDR ranges (#292)

- **`oauth.mtls.trusted-proxies` now takes CIDR ranges** (`10.0.0.0/8`,
  `fc00::/7`) and the `linklocal` / `uniquelocal` named ranges alongside the
  existing IP literals and `loopback`. The boot-time rejection that pointed at
  this issue is removed. A pod network is the shape operators actually have —
  the ingress replica's address is reassigned on every restart, so enumerating
  literals was not an option.

- **The matcher itself moved to `@o3co/auth-provider-core`**
  (`createTrustedProxyMatcher`). `src/proxy.mts` is gone; this package consumes
  core's, which is the same definition `http.trustProxy` validates against, so
  the two keys cannot drift into different dialects. Nothing exported from this
  package changed — the matcher was always internal.

  The two keys remain deliberately separate values: `http.trustProxy` decides
  whether `X-Forwarded-For` may rewrite `req.ip`, and turning that on must not
  silently start accepting forwarded client certificates. They share a
  vocabulary, not a setting. Matching is still against
  `req.socket.remoteAddress`, never `req.ip`.


### BREAKING — the certificate now comes from the TLS layer by default (#280)

- **`oauth.mtls.source` defaults to `"tls-layer"`, was `"header"`.** Enabling
  mTLS used to mean trusting an `X-Forwarded-Client-Cert` value from whoever
  opened the connection. The header was the credential and nothing proved it
  came from a proxy, so anyone who could reach the process — directly, or
  through an extra hop — could assert any client identity and mint a token
  bound to a certificate they do not hold. RFC 8705 §3 requires the certificate
  to come from the TLS layer or from an *authenticated* trusted proxy.

- **`oauth.mtls.source = "header"` now requires `oauth.mtls.trusted-proxies`**
  (new key, default `[]`). Boot fails with an operator-facing message when the
  header source is selected with an empty list. At request time, a forwarded
  certificate header from a peer outside the allowlist is rejected with
  `400 invalid_certificate` (audit reason `untrusted_proxy`, new
  `MtlsReasonCode` variant) and logged as `mtls_untrusted_proxy_rejected` with
  the observed peer address.

  Entries were the `"loopback"` keyword (`127.0.0.0/8` + `::1`) or IPv4 / IPv6
  literals; an IPv4 entry also matches the IPv4-mapped form a dual-stack
  listener reports. CIDR ranges were rejected at boot rather than silently never
  matching — #292 landed that vocabulary in the same release, so see the entry
  above: ranges and the `linklocal` / `uniquelocal` named ranges are accepted
  now.

  Matched against `req.socket.remoteAddress`, never `req.ip`: `req.ip` is
  rewritten from `X-Forwarded-For` whenever Express `trust proxy` is on, so
  using it would authenticate one header with another. For the same reason the
  list is separate from `http.trustProxy` and is not derived from it — enabling
  `X-Forwarded-For` parsing for rate limiting must not silently start accepting
  forwarded certificates.

  The rejection is a **throw, not a `null`**. Per CONTRIBUTING.md §4 `null`
  means the signal is absent; a header that is present but unauthenticated is
  invalid material, and invalid material fails the request rather than
  downgrading it to unbound. Returning `null` would hand an attacker a way to
  strip a binding off someone else's request by injecting a header.

  **Migration:** a deployment terminating TLS at a proxy must add
  `oauth.mtls.source = "header"` (previously the default) **and**
  `oauth.mtls.trusted-proxies` naming the address the proxy reaches the auth
  provider from. A deployment where the auth provider terminates TLS itself
  should drop `source` entirely and ensure the listener runs with
  `requestCert: true`.

### Added (#280)

- **Leaf certificate profile checks in `mode = "pki"`.** The leaf must carry
  `basicConstraints CA:FALSE` — a CA certificate is not a client credential,
  and binding a token to one binds it to an identity that can mint other
  identities — and, when `extendedKeyUsage` is present, it must include
  `clientAuth` (or `anyExtendedKeyUsage`), which is what stops a server
  certificate being presented as a client credential. A leaf with **no** EKU
  extension is still accepted: RFC 5280 §4.2.1.12 makes the extension a
  restriction rather than a grant, so absence is unconstrained.

  These run before the chain walk, so a mis-issued certificate reports the
  certificate as the problem instead of "no path to trust anchor".

- **The terminal trust anchor must itself be a CA.** The anchor list is
  operator-supplied; a paste error putting an end-entity certificate in it
  previously terminated the walk successfully.

- New `ext-*` test fixtures: a second single-hop chain whose leaves differ only
  in `basicConstraints` / `extendedKeyUsage`, so a profile rejection cannot be
  caused by anything else.

### Known gap (#280 scope-out)

- **Revocation is still not checked.** No CRL (RFC 5280 §6.3) and no OCSP
  (RFC 6960): a revoked client certificate keeps binding tokens until it
  expires. This was deliberately left out of #280 and is tracked, together with
  the remaining RFC 5280 path-validation checks (name constraints, critical
  extension processing, issuer `keyCertSign`, `pathLenConstraint`, policy
  processing, algorithm policy), in
  [#341](https://github.com/o3co/auth.provider/issues/341). Mitigation until
  then: short certificate lifetimes, rotation, and a minimal `trusted-cas` set
  per RFC 8705 §7.4.

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
  See ADR `packages/core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md`
  for the design rationale.
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

Implements Wave 2 Phase 3 Sub-PR 3b per the internal design spec.

### Added (Phase 3 Sub-PR 3a)

- Initial `@o3co/auth-provider-mtls` package skeleton.
- `pemToDer` + `derToPem` codec helpers (internal).
- `parseEnvoyXfccHeader` + `parsePlainPemHeader` dialect parsers (internal).
- `computeCertThumbprint` (RFC 8705 §3.1 — base64url-encoded SHA-256 hash of DER, trailing `=` padding stripped).
- `ClientCertificate` type + `parseDerToCertificate`.
- `MtlsError` + `MtlsReasonCode` union.

Implements Wave 2 Phase 3 Sub-PR 3a per the internal design spec.
