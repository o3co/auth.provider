# @o3co/auth-provider-mtls

mTLS ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)) sender-constrained access token support for `@o3co/auth-provider`.

> **Status:** Phase 3 (Wave 2) complete. The package ships `createMtlsMechanism` (header / tls-layer sources, envoy + plain-pem dialects), narrow-mode PKI chain validation with explicit cryptographic signature verification at every hop, `mtlsModule` wiring via the core `tokenBindingMechanisms` contribution slot, grant-side `cnf.x5t#S256` emission, and the §9.2 mTLS refresh-time enforcement matrix (5 rows + compound-`cnf` pre-matrix reject + mechanism-boundary regression). RT binding for public clients per RFC 8705 §4 is enforced end-to-end.

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

## Trusted-Proxy Security Guidance

RFC 8705 §3 accepts a client certificate from the TLS layer, or from an **authenticated** trusted proxy. `source = "header"` is the second shape, and the word doing the work is *authenticated*.

### `trusted-proxies` — required, and what it actually proves

`source = "header"` requires a non-empty `oauth.mtls.trusted-proxies`; boot fails otherwise. A forwarded certificate header presented by any other peer is rejected with `400 invalid_certificate` (audit reason `untrusted_proxy`), and the observed peer address is logged as `mtls_untrusted_proxy_rejected` so a missing allowlist entry is distinguishable from an attack.

```hocon
oauth.mtls.trusted-proxies = ["loopback"]        # sidecar proxy on the same host / pod
oauth.mtls.trusted-proxies = ["10.0.4.7", "10.0.4.8"]
```

Each entry is the `"loopback"` keyword (`127.0.0.0/8` + `::1`) or an IPv4 / IPv6 literal. An IPv4 entry also matches the IPv4-mapped form (`::ffff:10.0.4.7`) that a dual-stack listener reports. **CIDR ranges are not accepted yet** — they are rejected at boot rather than silently never matching; the shared trusted-proxy range vocabulary arrives with [#292](https://github.com/o3co/auth.provider/issues/292).

The check runs against `req.socket.remoteAddress` — the peer that opened the connection — and deliberately **not** against `req.ip`, which `X-Forwarded-For` rewrites whenever Express `trust proxy` is on. Authenticating one header with another would prove nothing.

For the same reason this list is **separate from `http.trustProxy`** and is not derived from it. `http.trustProxy` decides whether `X-Forwarded-For` may rewrite `req.ip` for rate limiting and URL reconstruction; turning that on must not silently start accepting forwarded client certificates.

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

`mode = "pki"` enables a **narrow** chain-validation check set — **NOT full [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) path validation**. Operators needing full path validation MUST keep `mtlsModule` disabled until a future `mode = "full-pki"` arm lands (see [RFC 8705 §7.5](https://www.rfc-editor.org/rfc/rfc8705#section-7.5)).

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

- **CRL / OCSP revocation** (RFC 5280 §6.3 + RFC 6960). **A revoked client certificate keeps binding tokens until it expires.** Rely on short cert lifetimes and key rotation. Tracked with the rest of this list in [#341](https://github.com/o3co/auth.provider/issues/341).
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

**Recommend keeping `mtlsModule` disabled** for deployments requiring regulatory-grade path validation, until a future `mode = "full-pki"` arm ships backed by a real path-validation library.

### RFC 8705 §7.4 — trust-anchor scope

> "An attacker could try to impersonate a client using a certificate with the same subject … the authorization server SHOULD only accept … a limited number of CAs."

The `trusted-cas` config is a manual allowlist — operators are responsible for sizing it narrowly. Typically **a single private CA** for M2M deployments. A long list of public/commercial CAs would expose the AS to cross-CA cert-forgery attacks (any compromised CA in the list can mint a colliding-subject cert).

### RFC 8705 §7.5 — established X.509 library

> "Implementors SHOULD use an established and well-tested X.509 library … and SHOULD NOT attempt to write their own X.509 certificate validation procedures."

The parsing layer satisfies this SHOULD (everything routes through `node:crypto`'s `X509Certificate`). The **path-validation orchestration is hand-rolled** in this package because Phase 3 explicitly defers the full RFC 5280 procedure. The future `mode = "full-pki"` arm will close the gap by delegating path validation to a library such as `pkijs` or a `node-forge`-based wrapper.

## Boot-time fail-loud invariants

`mtlsModule` rejects three specific misconfigurations at boot rather than failing silently at runtime:

1. **`source = "header"` with an empty `trusted-proxies`** — the forwarded header would then be the credential, accepted from anyone routable to the process. There is no safe default here: an empty list cannot mean "trust the usual proxies", and trusting none of them at runtime would fail every request with no boot signal. See [#280](https://github.com/o3co/auth.provider/issues/280).

2. **`mode = "pki"` with an empty `trusted-cas`** — without trust anchors, chain validation cannot proceed. Failing boot directs the operator straight to the misconfig instead of either silently failing open (no validation) or failing closed on every request (no audit signal).

3. **`mode = "pki"` with `source = "tls-layer"`** — the narrow PKI mode requires the intermediate chain (e.g., the Envoy XFCC `Chain=` parameter). TLS-layer full-chain extraction is deferred. The combination would fail-open or fail-closed without operator visibility; rejecting at boot prevents the ambiguity. Use `source = "header"` with `cert-header-dialect = "envoy"` and a `trusted-proxies` allowlist for PKI mode, or use `mode = "self-signed"` with the `tls-layer` source. Now that `tls-layer` is the default source this combination is easier to reach; lifting it is part of [#341](https://github.com/o3co/auth.provider/issues/341).

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
