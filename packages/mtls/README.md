# @o3co/auth-provider-mtls

mTLS ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)) sender-constrained access token support for `@o3co/auth-provider`.

> **Status:** Phase 3 (Wave 2). Sub-PR 3a + 3b ship the package skeleton, dialect parsers, thumbprint, `createMtlsMechanism` factory, narrow-mode PKI chain validation, and `mtlsModule` wiring. Grant-side `cnf.x5t#S256` emission + refresh-token binding for public clients land in Sub-PR 3c.

## Overview

Sender-constrained access tokens per RFC 8705 §3 — Mutual TLS Client Certificate-Bound Access Tokens. The mechanism extracts the client cert presented during the TLS handshake (or forwarded by a reverse proxy), computes the SHA-256 thumbprint of the DER encoding (RFC 8705 §3.1), and emits it as the `cnf["x5t#S256"]` claim on the issued access token (and on refresh tokens for public clients per RFC 8705 §4).

This package plugs into the existing `tokenBindingMw` from `@o3co/auth-provider-core` (Phase 1b) and emits a `TokenBinding` with `kind: "mtls"`.

## Quick start

```ts
// composition root
import { mtlsModule } from "@o3co/auth-provider-mtls";
import { dpopModule } from "@o3co/auth-provider-dpop"; // optional, can run alongside

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
# application.conf — opt in to mTLS at the AS
oauth.mtls {
  enabled = true
  source = "header"                              # or "tls-layer"
  cert-header = "x-forwarded-client-cert"
  cert-header-dialect = "envoy"                  # or "plain-pem"
  mode = "self-signed"                           # or "pki" (see PKI Mode Scope)
}
```

`oauth.tokenBinding.dispatch-policy` is shared with `dpopModule`:

```hocon
oauth.tokenBinding.dispatch-policy = "intent-explicit"   # or "strict-mutual-exclusion"
```

## Source modes

| `source` | Where the cert comes from | When to use |
| --- | --- | --- |
| `"header"` (default) | A forwarded-cert header set by a trusted reverse proxy (Envoy, nginx). Pair with `cert-header` + `cert-header-dialect`. | The auth provider sits behind a TLS-terminating proxy. **Common deployment shape.** |
| `"tls-layer"` | `req.socket.getPeerCertificate()` — the live TLS handshake. Requires the auth provider's listener to be TLS-terminated with `requestCert = true`. | The auth provider terminates TLS itself (less common at scale; preferred for simple deployments where the AS is the edge). |

## Trusted-Proxy Security Guidance

When `source = "header"`, the AS **trusts the reverse proxy** to:

1. **Terminate TLS and successfully authenticate the client cert.** The forwarded header MUST reflect a cert that the proxy already validated; the AS does not re-do the handshake.
2. **Block any forwarded-cert header coming from upstream.** Anyone who can set `x-forwarded-client-cert` on a request to the AS impersonates any client at will. The proxy must **strip the header from incoming requests** before injecting its own value.
3. **Connect to the AS over an authenticated channel** — TLS to the AS, network-segmented loopback / VPC, or both — so an attacker cannot bypass the proxy and reach the AS directly with a forged header.

**Failure to enforce any of (2) or (3) is a complete bypass of the cert binding** — there is no in-package defense the AS can apply (we cannot distinguish a legitimate proxy-injected header from an attacker-injected one). The header dialect parsers reject obviously malformed input but offer **no security against a misconfigured deployment**.

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

> **Note:** nginx does not emit Envoy-format XFCC. The Phase 3 `cert-header-dialect` enumeration is `"envoy" | "plain-pem"` — `"plain-pem"` is what nginx + similar minimal proxies should use, NOT an nginx-specific XFCC variant (which is out of scope for Stage 1 — see [#1.3 of the spec](../../.claude/superpowers/specs/2026-05-18-wave-2-phase-3-mtls-spec.md)).
>
> To strip any inbound header before nginx injects its own, add `proxy_set_header X-Forwarded-Client-Cert "";` to a higher-priority location, or use a sanitization filter on the upstream.

## PKI Mode Scope

`mode = "pki"` enables a **narrow** chain-validation check set — **NOT full [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) path validation**. Operators needing full path validation MUST keep `mtlsModule` disabled until a future `mode = "full-pki"` arm lands (see [RFC 8705 §7.5](https://www.rfc-editor.org/rfc/rfc8705#section-7.5)).

### Checks performed in `mode = "pki"`

For each presented chain `leaf → intermediate₁ → … → intermediateₙ → root`:

1. Leaf cert validity window (`notBefore <= now <= notAfter`).
2. Hop-by-hop walk with `fingerprint256` cycle detection.
3. For each intermediate: validity window + `basicConstraints.CA === true` (RFC 5280 §4.2.1.9 — non-CA cannot sign certs).
4. Trust-anchor match via `X509Certificate.checkIssued()`, which internally enforces issuer-DN match **and** the CA-bit on the would-be-issuer (OpenSSL `X509_check_issued`).
5. Anchor validity window.

### Checks NOT performed (load-bearing scope-out)

The narrow mode does **not** check:

- **Name constraints** (RFC 5280 §4.2.1.10) — CRITICAL extension. If a trust anchor carries `nameConstraints`, the chain walk does not enforce them.
- **Policy constraints / policy mappings / inhibit-anyPolicy** (RFC 5280 §4.2.1.11–13).
- **Full critical-extension handling** (RFC 5280 §6.1.2 requires every critical extension to be processed; narrow mode handles only the ones explicitly listed above).
- **CRL / OCSP revocation** (RFC 5280 §6.3 + RFC 6960). Rely on short cert lifetimes and key rotation instead.
- **Path length constraints** (RFC 5280 §4.2.1.9 `pathLenConstraint`).
- **Algorithm policy** (RFC 5280 §4.1.1.2 + §6.1.4). Falls through to Node's underlying signature verification, which honors the OS / OpenSSL configuration.

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

`mtlsModule` rejects two specific misconfigurations at boot rather than failing silently at runtime:

1. **`mode = "pki"` with an empty `trusted-cas`** — without trust anchors, chain validation cannot proceed. Failing boot directs the operator straight to the misconfig instead of either silently failing open (no validation) or failing closed on every request (no audit signal).

2. **`mode = "pki"` with `source = "tls-layer"`** — the narrow PKI mode requires the intermediate chain (e.g., the Envoy XFCC `Chain=` parameter). TLS-layer full-chain extraction is deferred. The combination would fail-open or fail-closed without operator visibility; rejecting at boot prevents the ambiguity. Use `source = "header"` with `cert-header-dialect = "envoy"` for PKI mode, or use `mode = "self-signed"` with `tls-layer` source.

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
