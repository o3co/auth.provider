# @o3co/auth-provider-mtls

mTLS ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)) sender-constrained access token support for `@o3co/auth-provider`.

> **Status:** complete — shipped in v0.8.0 as phase 3 of the token-binding cluster (roadmap Wave 2; see [docs/design-campaign-index.md](../../docs/design-campaign-index.md)). The package ships `createMtlsMechanism` (header / tls-layer sources, envoy + plain-pem dialects), narrow-mode PKI chain validation with explicit cryptographic signature verification at every hop, `mtlsModule` wiring via the core `tokenBindingMechanisms` contribution slot, grant-side `cnf.x5t#S256` emission, and the mTLS rows of the refresh-time token-binding enforcement matrix (the "§9.2 matrix", core `confirmationMatch.mts` — 5 rows + compound-`cnf` pre-matrix reject + mechanism-boundary regression). RT binding for public clients per RFC 8705 §4 is enforced end-to-end.

## Overview

Sender-constrained access tokens per RFC 8705 §3 — Mutual TLS Client Certificate-Bound Access Tokens. The mechanism extracts the client cert presented during the TLS handshake (or forwarded by a reverse proxy), computes the SHA-256 thumbprint of the DER encoding (RFC 8705 §3.1), and emits it as the `cnf["x5t#S256"]` claim on the issued access token (and on refresh tokens for public clients per RFC 8705 §4).

This package plugs into the existing `tokenBindingMw` from `@o3co/auth-provider-core` (Phase 1b) and emits a `TokenBinding` with `kind: "mtls"`.

## Quick start

```ts
// composition root — mtls alone, or alongside dpop (see "Cross-mechanism
// dispatch" below for the unified DispatchPolicy).
import { mtlsModule } from "@o3co/auth-provider-mtls";
import { dpopModule } from "@o3co/auth-provider-dpop"; // optional, runs together

await createApp({
  modules: [
    /* ... existing modules ... */
    dpopModule,
    mtlsModule,
  ],
  bootstrapComponents: { config, /* logger ... */ },
});
```

```hocon
# application.conf — opt in to mTLS at the AS.
# The AS terminates TLS itself: the certificate comes from the handshake.
oauth.mtls {
  enabled = true
  mode = "self-signed"                           # or "pki" (see PKI Mode Scope)
  # source defaults to "tls-layer" — nothing else to set.
}
```

Behind a TLS-terminating reverse proxy, the certificate arrives in a header
instead, and the proxy must be named explicitly:

```hocon
oauth.mtls {
  enabled = true
  source = "header"
  cert-header = "x-forwarded-client-cert"
  cert-header-dialect = "envoy"                  # or "plain-pem"
  trusted-proxies = ["loopback"]                 # REQUIRED for source = "header"
  mode = "self-signed"
}
```

`oauth.tokenBinding.dispatch-policy` is shared with `dpopModule`:

```hocon
oauth.tokenBinding.dispatch-policy = "intent-explicit"   # or "strict-mutual-exclusion"
```

## Cross-mechanism dispatch (DPoP + mTLS)

When both `@o3co/auth-provider-dpop` and `@o3co/auth-provider-mtls` are installed, core composes a **single** `tokenBindingMw` from both modules' contributions. The configured `oauth.tokenBinding.dispatch-policy` arbitrates cross-mechanism:

- `"intent-explicit"` (default): explicit-intent mechanisms (DPoP) win over ambient mechanisms (mTLS) on a single request. ≥2 explicit-intent mechanisms succeeding → 400 `invalid_request`.
- `"strict-mutual-exclusion"`: any 2+ mechanisms succeeding → 400 `invalid_request`.

Set it once at the application layer:

```hocon
oauth.tokenBinding.dispatch-policy = "intent-explicit"   # or "strict-mutual-exclusion"
```

The key is declared by core's bundled config schema (single source of truth). It applies across all installed binding-mechanism modules.

## Source modes

| `source` | Where the cert comes from | When to use |
| --- | --- | --- |
| `"tls-layer"` (default) | `req.socket.getPeerCertificate()` — the live TLS handshake. Requires the auth provider's listener to be TLS-terminated with `requestCert = true`. | The auth provider terminates TLS itself. **This is the RFC 8705 §3 shape**: the certificate is proven by the handshake rather than asserted by a header, so there is nothing to forge. |
| `"header"` | A forwarded-cert header set by a trusted reverse proxy (Envoy, nginx). Pair with `cert-header`, `cert-header-dialect`, and a **required** `trusted-proxies` allowlist. | The auth provider sits behind a TLS-terminating proxy. Common at scale, and safe only to the extent the proxy hop is. |

## Discovery metadata

When `oauth.mtls.enabled = true`, this module contributes `tls_client_certificate_bound_access_tokens: true` (RFC 8705 §3.3) to `/.well-known/openid-configuration`. While disabled it contributes nothing, and the RFC already reads an omitted flag as `false`.

The flag does **not** vary with `source`: both source modes above produce the same `cnf["x5t#S256"]` on the issued token, and §3.3 describes the token, not the transport the certificate arrived over.

This is the only field contributed, on purpose. This package implements RFC 8705 **§3 token binding**, not **§2 mTLS client authentication**, so `tls_client_auth` / `self_signed_tls_client_auth` never appear in `token_endpoint_auth_methods_supported` — the token endpoint does not accept a certificate as a client credential.

## Trusted-Proxy Security Guidance

RFC 8705 §3 accepts a client certificate from the TLS layer, or from an **authenticated** trusted proxy. `source = "header"` is the second shape, and the word doing the work is *authenticated*.

### `trusted-proxies` — required, and what it actually proves

`source = "header"` requires a non-empty `oauth.mtls.trusted-proxies`; boot fails otherwise. A forwarded certificate header presented by any other peer is rejected with `400 invalid_certificate` (audit reason `untrusted_proxy`), and the observed peer address is logged as `mtls_untrusted_proxy_rejected` so a missing allowlist entry is distinguishable from an attack.

```hocon
oauth.mtls.trusted-proxies = ["loopback"]        # sidecar proxy on the same host / pod
oauth.mtls.trusted-proxies = ["10.0.4.7", "10.0.4.8"]
oauth.mtls.trusted-proxies = ["10.0.0.0/8"]      # a pod network, where the address changes per restart
```

Entries use the shared trusted-proxy vocabulary owned by `@o3co/auth-provider-core` — which is also Express's own `trust proxy` vocabulary ([#292](https://github.com/o3co/auth.provider/issues/292)):

- an **IPv4 / IPv6 literal**. An IPv4 entry also matches the IPv4-mapped form (`::ffff:10.0.4.7`) that a dual-stack listener reports.
- a **CIDR range** — `10.0.0.0/8`, `fc00::/7`.
- a **named range** — `loopback` (`127.0.0.0/8` + `::1`), `linklocal`, `uniquelocal`.

A hostname, a typo'd keyword or a malformed prefix length fails at boot rather than becoming a rule that silently never matches.

The check runs against `req.socket.remoteAddress` — the peer that opened the connection — and deliberately **not** against `req.ip`, which `X-Forwarded-For` rewrites whenever Express `trust proxy` is on. Authenticating one header with another would prove nothing.

For the same reason this list is **separate from `http.trustProxy`** and is not derived from it. The two share a vocabulary, not a value: `http.trustProxy` decides whether `X-Forwarded-For` may rewrite `req.ip` for rate limiting, and turning that on must not silently start accepting forwarded client certificates.

An address allowlist is a network-level control, not a cryptographic one. It is necessary, not sufficient.

### What the proxy must still do

1. **Terminate TLS and successfully authenticate the client cert.** The forwarded header MUST reflect a cert that the proxy already validated; the AS does not re-do the handshake.
2. **Block any forwarded-cert header coming from upstream.** The proxy must **strip the header from incoming requests** before injecting its own value — otherwise a client simply asks the proxy to forward its forgery.
3. **Reach the AS over a channel an attacker cannot occupy.** The allowlist authenticates a source address, and a source address is only as trustworthy as the network under it. Keep the proxy → AS hop on a segment where addresses cannot be spoofed or borrowed (loopback, a private VPC subnet), and prefer TLS on that hop as well.

**Failure to enforce (1) or (2) is still a complete bypass of the cert binding**, and no allowlist can detect it — a legitimate proxy forwarding a header it should have stripped is indistinguishable from one forwarding a header it minted. The header dialect parsers reject obviously malformed input but offer **no security against a misconfigured proxy**.

### Sample reverse-proxy snippets

**Envoy** — native XFCC dialect (this IS the format `cert-header-dialect = "envoy"` parses):

```yaml
http_filters:
- name: envoy.filters.http.router
forward_client_cert_details: SANITIZE_SET     # strip incoming + set own
set_current_client_cert_details:
  cert: true
  chain: true                                  # populates Chain= for PKI mode
  uri: true
  hash: true
```

`SANITIZE_SET` enforces guidance (2) — Envoy drops any incoming XFCC header and writes its own based on the validated client cert.

**nginx** — plain-PEM dialect using `$ssl_client_escaped_cert`:

```nginx
location / {
  proxy_set_header X-Forwarded-Client-Cert $ssl_client_escaped_cert;
  proxy_pass http://auth-provider;
}
```

`$ssl_client_escaped_cert` is the URL-encoded PEM of the validated client leaf cert. The `cert-header-dialect = "plain-pem"` parser auto-decodes the percent-encoding.

Either way, add the address nginx or Envoy reaches the auth provider from to `oauth.mtls.trusted-proxies` — `"loopback"` when they share a host or pod, the pod / instance address otherwise.

> **Note:** nginx does not emit Envoy-format XFCC. The Phase 3 `cert-header-dialect` enumeration is `"envoy" | "plain-pem"` — `"plain-pem"` is what nginx + similar minimal proxies should use, NOT an nginx-specific XFCC variant (which is out of scope for Stage 1).
>
> To strip any inbound header before nginx injects its own, add `proxy_set_header X-Forwarded-Client-Cert "";` to a higher-priority location, or use a sanitization filter on the upstream.

## PKI Mode Scope

There are two PKI arms, and the difference between them is not a matter of degree.

- **`mode = "pki"`** — a **narrow** chain-validation check set, **not full [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) path validation** and with **no revocation**. Unchanged since #280.
- **`mode = "full-pki"`** — RFC 5280 §6 path validation with revocation, added by [#341](https://github.com/o3co/auth.provider/issues/341). This is the arm to use when a revoked certificate must stop working.

### Checks performed in `mode = "pki"`

For each presented chain `leaf → intermediate₁ → … → intermediateₙ → root`:

1. Leaf cert validity window (`notBefore <= now <= notAfter`).
2. **Leaf certificate profile**: `basicConstraints.CA === false` (a CA certificate is not a client credential — binding a token to one binds it to an identity that can mint other identities), and, when `extendedKeyUsage` is present, it must include `clientAuth` or `anyExtendedKeyUsage` (RFC 5280 §4.2.1.12). A leaf with **no** EKU extension is accepted: §4.2.1.12 makes the extension a restriction, not a grant, so absence is unconstrained.
3. Hop-by-hop walk with `fingerprint256` cycle detection.
4. For each intermediate: validity window + `basicConstraints.CA === true` (RFC 5280 §4.2.1.9 — non-CA cannot sign certs).
5. **Pair check at every hop**: `X509Certificate.checkIssued()` (DN / AKID / SKID match) **AND** `X509Certificate.verify(issuer.publicKey)` (cryptographic signature). Both required — `checkIssued` alone does NOT verify the signature (OpenSSL `X509_check_issued` documents this explicitly), so an attacker omitting or crafting AKID could otherwise mint a forged cert with matching DN.
6. Anchor validity window, and `basicConstraints.CA === true` on the anchor itself — the anchor list is operator-supplied, and a paste error putting an end-entity certificate in it would otherwise terminate the walk successfully.

### Checks NOT performed (load-bearing scope-out)

The narrow mode does **not** check:

Everything in this list is checked by `mode = "full-pki"`, except where noted.

- **CRL / OCSP revocation** (RFC 5280 §6.3 + RFC 6960). **A revoked client certificate keeps binding tokens until it expires.** Rely on short cert lifetimes and key rotation, or use `full-pki`, which checks CRLs. (OCSP remains unimplemented in both arms.)
- **Name constraints** (RFC 5280 §4.2.1.10) — CRITICAL extension. If a trust anchor carries `nameConstraints`, the chain walk does not enforce them.
- **Policy constraints / policy mappings / inhibit-anyPolicy** (RFC 5280 §4.2.1.11–13).
- **Full critical-extension handling** (RFC 5280 §6.1.2 requires every critical extension to be processed; narrow mode handles only the ones explicitly listed above).
- **`keyUsage` `keyCertSign` on issuers** (RFC 5280 §4.2.1.3). Node's `X509Certificate.keyUsage` returns *extended* key usage OIDs, not the `keyUsage` bit string, so this needs ASN.1 parsing of the DER.
- **Path length constraints** (RFC 5280 §4.2.1.9 `pathLenConstraint`).
- **Algorithm policy** (RFC 5280 §4.1.1.2 + §6.1.4). Falls through to Node's underlying signature verification, which honors the OS / OpenSSL configuration.

### Trusted-CA entries (literal PEM or `file:` path)

Each entry in `trusted-cas` is either:

- **Literal PEM** — paste the `-----BEGIN CERTIFICATE-----` block directly into HOCON via triple-quoted string.
- **`file:<path>`** — the file at `<path>` is read synchronously at boot. Use absolute paths or rely on HOCON env-substitution for portability.

```hocon
oauth.mtls {
  mode = "pki"
  trusted-cas = [
    "file:/etc/auth-provider/ca/private-root.pem",
    """-----BEGIN CERTIFICATE-----
    MIID...
    -----END CERTIFICATE-----"""
  ]
}
```

A missing file or unparseable PEM aborts boot with an index-prefixed error message — operators see exactly which entry failed.

### When to disable PKI mode

Use `mode = "self-signed"` (the default) when the AS controls all client certs — the [Self-Signed Mutual-TLS](https://www.rfc-editor.org/rfc/rfc8705#section-2.2) profile from RFC 8705 §2.2. The binding remains secure because the SHA-256 thumbprint of the leaf cert acts as the credential — no chain trust is needed for the binding to work.

Deployments requiring regulatory-grade path validation should use `mode = "full-pki"` below rather than `"pki"`.

### RFC 8705 §7.4 — trust-anchor scope

> "An attacker could try to impersonate a client using a certificate with the same subject … the authorization server SHOULD only accept … a limited number of CAs."

The `trusted-cas` config is a manual allowlist — operators are responsible for sizing it narrowly. Typically **a single private CA** for M2M deployments. A long list of public/commercial CAs would expose the AS to cross-CA cert-forgery attacks (any compromised CA in the list can mint a colliding-subject cert).

### RFC 8705 §7.5 — established X.509 library

> "Implementors SHOULD use an established and well-tested X.509 library … and SHOULD NOT attempt to write their own X.509 certificate validation procedures."

In `mode = "pki"` the parsing layer satisfies this SHOULD (everything routes through `node:crypto`'s `X509Certificate`) but the **path-validation orchestration is hand-rolled**.

`mode = "full-pki"` closes that: path validation is delegated to [`pkijs`](https://pkijs.org)'s `CertificateChainValidationEngine`, which implements RFC 5280 §6 including the policy tree and name-constraint processing. What is *not* delegated is listed explicitly in the next section — silently assuming a library covers something it does not is the failure mode this SHOULD exists to prevent.

## `mode = "full-pki"` (#341)

RFC 5280 §6 path validation with revocation. Requires a non-empty `trusted-cas` and an explicit `full-pki.revocation` block. Works with either `source`; under `tls-layer` the chain is read from the TLS session via `getPeerCertificate(true)`.

### What the library does, and what this package still owns

`pkijs` performs path building, per-hop signature verification, validity windows, `basicConstraints`, `keyUsage` (`keyCertSign` / `cRLSign`) on CAs, name constraints, and the certificate-policy tree. Four things it does **not** do are implemented here, and it is worth being precise about why:

1. **`pathLenConstraint`** (§4.2.1.9) — not implemented by the engine at all. A CA that published `pathlen:0` precisely to stop sub-CAs being minted under it would otherwise have said so for nothing.
2. **Algorithm policy** (§6.1.4) — left to local policy by the RFC, which in practice means whatever the OpenSSL build accepts. Applied here to **every** certificate on the path, anchors included: a chain is only as strong as its weakest hop. SHA-1 has no name in the config vocabulary, so no configuration can permit it.
3. **Critical extension processing** (§6.1.2) — the engine applies this rule only to the CA certificates in the path. **The leaf is skipped.** So a client certificate carrying a critical extension nobody understands would validate cleanly. This package applies the rule uniformly to the whole path.
4. **Revocation availability.** The engine skips its revocation block entirely when handed no CRLs, and returns *valid*. "The CRL server is down" and "this certificate is not revoked" therefore reach it as the same input. That is the single most dangerous default in this area, and it is why revocation here is a two-pass affair with the availability decision made **before** the engine is consulted.

The leaf-certificate profile (`CA:FALSE`, and `clientAuth` when `extendedKeyUsage` is present) is the *same code* the narrow mode runs — imported, not restated, so the stricter arm cannot silently become weaker than the looser one on the leaf.

### Revocation has no defaults, on purpose

`mode = "full-pki"` **fails boot** unless `full-pki.revocation.mode` and `.on-unavailable` are both set.

"The CRL endpoint is unreachable" and "the certificate is not revoked" are different facts. Whether an outage should block logins or be waved through depends on whether a revoked certificate continuing to work for a while is worse than an availability incident — which only the operator knows. A library that picks silently picks wrong for half its deployments, invisibly, and only during the outage that makes it matter. So it is stated, or boot fails:

```hocon
oauth.mtls {
  mode = "full-pki"
  trusted-cas = ["file:/etc/auth-provider/ca/private-root.pem"]
  full-pki.revocation {
    mode = "crl"              # or "disabled" — an explicit acceptance of the gap
    on-unavailable = "reject" # or "allow", logged at warn on every use
    allowed-hosts = ["crl.example.com"]
  }
}
```

`mode = "ocsp"` is **refused at boot**, not accepted and ignored. OCSP is not implemented. (Note also that stapled OCSP is not an option here even in principle: `status_request` stapling covers the *server's* certificate, and Node exposes no stapled response for a **client** certificate on the server side. An OCSP arm would be responder-fetch only.)

A certificate is treated as *unavailable* — and therefore subject to `on-unavailable` — when it names no distribution point, when the CRL cannot be fetched or parsed, when the CRL has expired, when it carries no `nextUpdate` at all (without one there is no way to distinguish a current CRL from one captured before a revocation and replayed), when its signature does not verify against the issuing CA, or when it carries a critical extension this validator does not process (RFC 5280 §5.2 forbids using such a CRL, and pkijs would otherwise have reported it as a bad signature — [#447](https://github.com/o3co/auth.provider/issues/447)).

**Partitioned, indirect and delta CRLs are not supported.** RFC 5280 lets a CA split its revocation information — by reason code across several distribution points (`reasons` on the point, `onlySomeReasons` on the CRL), by certificate type or distribution point (`issuingDistributionPoint`), into a base CRL plus deltas (`deltaCRLIndicator`), or by delegating publication to another issuer (`cRLIssuer`, `indirectCRL`). pkijs accepts every one of those extensions as well-known and then ignores them, which would read a CRL scoped to user certificates as the complete list for an intermediate, or a delta as the complete list for anyone. None of them is implemented here. Each is *recognised* and reported as unavailable under its own reason — `unsupported_distribution_point` for a point carrying `reasons` or `cRLIssuer` (nothing is fetched), `unsupported_crl_scope` for a delta or a CRL whose `issuingDistributionPoint` states any scope — and `on-unavailable` then applies: `"reject"` refuses the certificate, `"allow"` accepts it with the `mtls_revocation_unavailable_allowed` warn line. What never happens is such a CRL being read as authoritative. A base CRL that merely points at a delta (`freshestCRL`) is used as the base it is; the delta is not fetched, so a revocation published only in a delta is not seen until the next base CRL ([#446](https://github.com/o3co/auth.provider/issues/446)).

**Several distribution points.** Names *within* one distribution point are alternative ways to obtain the same CRL (RFC 5280 §4.2.1.13) and are tried in order; separate distribution points are not assumed to be. Under `"reject"`, a certificate is refused when *any* of its distribution points yields no usable CRL, even if another did — this validator cannot tell from one fetched CRL that the CA's other points were redundant, and `"reject"` means not guessing. Under `"allow"`, the CRLs that were obtained are checked and the point that was not is logged as `mtls_revocation_partially_unavailable_allowed`, distinct from the line for a certificate that was not checked at all. Points that name no HTTP(S) URI (an LDAP URI, a directory name) are outside what this validator speaks and are ignored rather than counted as failed, so a directory-backed CA that lists an LDAP point beside an HTTP one is not refused for it.

### Fetching a URL out of a certificate

A CRL distribution point is a URL chosen by someone else, and retrieving it makes this process issue a request from inside your network — the classic SSRF shape, with `http://169.254.169.254/…` reachable from most cloud workloads. Two layers bound it:

1. **Path validation runs first.** Distribution points are read only from a path that has already been validated to a configured trust anchor, so an arbitrary client certificate cannot cause an outbound request at all.
2. **`revocation.allowed-hosts`**, which is **required and non-empty** when `mode = "crl"`. Layer 1 makes the URL come from a CA you trust; this layer means trusting a CA to *issue certificates* is not the same as trusting it to *name destinations inside your network*. It is the same separation `trusted-proxies` draws for forwarded certificate headers.

On top of those: redirects are never followed (a redirect names a second destination neither layer vetted), responses are capped by byte count read incrementally rather than by the responder's `Content-Length` claim, fetches time out, credentials in the URL are refused, and only `http`/`https` are spoken. CRLs are cached until `nextUpdate` or `cache-ttl-seconds`, whichever is sooner; a stale CRL is deliberately not cached, so a responder that has stopped publishing cannot pin us to it. A distribution point that could not be used — unreachable, unparseable, stale, or serving a CRL of a shape listed above — is remembered as unavailable for a 30-second window, so an outage costs one probe per window rather than one per request; a CRL whose signature does not verify is the one outcome never remembered in either direction.

## Boot-time fail-loud invariants

`mtlsModule` rejects five specific misconfigurations at boot rather than failing silently at runtime:

1. **`source = "header"` with an empty `trusted-proxies`** — the forwarded header would then be the credential, accepted from anyone routable to the process. There is no safe default here: an empty list cannot mean "trust the usual proxies", and trusting none of them at runtime would fail every request with no boot signal. See [#280](https://github.com/o3co/auth.provider/issues/280).

2. **`mode = "pki"` with an empty `trusted-cas`** — without trust anchors, chain validation cannot proceed. Failing boot directs the operator straight to the misconfig instead of either silently failing open (no validation) or failing closed on every request (no audit signal).

3. **`mode = "pki"` with `source = "tls-layer"`** — the *narrow* PKI mode requires the intermediate chain (e.g., the Envoy XFCC `Chain=` parameter), and reads it from nowhere else. Use `source = "header"` with `cert-header-dialect = "envoy"` and a `trusted-proxies` allowlist, use `mode = "self-signed"` with the `tls-layer` source, or use **`mode = "full-pki"`, which reads the chain from the TLS session** and is not subject to this restriction (#341).

4. **`mode = "full-pki"` without `full-pki.revocation.mode` and `.on-unavailable`** — see "Revocation has no defaults, on purpose" above.

5. **`mode = "full-pki"` with `revocation.mode = "crl"` and an empty `revocation.allowed-hosts`** — an empty allowlist would mean "fetch from any destination a certificate names".

## Hash algorithm

[RFC 8705 §7.2](https://www.rfc-editor.org/rfc/rfc8705#section-7.2) is explicit that SHA-256 is sufficient for the leaf-cert thumbprint binding — operators do not need to configure or rotate the algorithm. The Phase 3 implementation hardcodes SHA-256 with no allowlist; this is intentional and matches the RFC's normative `x5t#S256` claim name.

## API surface

```ts
export type { CertHeaderDialect } from "@o3co/auth-provider-mtls";  // "envoy" | "plain-pem"
export type { ClientCertificate } from "@o3co/auth-provider-mtls";  // diagnostic struct
export { MtlsError, type MtlsErrorCode, type MtlsReasonCode } from "@o3co/auth-provider-mtls";
export { computeCertThumbprint } from "@o3co/auth-provider-mtls";
export { createMtlsMechanism, type MtlsMechanismOptions } from "@o3co/auth-provider-mtls";
export { mtlsConfigSchema, mtlsModule } from "@o3co/auth-provider-mtls";
```

The dialect parsers, PKI chain walker, and PEM↔DER codec are intentionally **internal** — consumers compose dialects via the `cert-header-dialect` config key, not via direct import.

## License

Apache-2.0 © 1o1 Co. Ltd.
