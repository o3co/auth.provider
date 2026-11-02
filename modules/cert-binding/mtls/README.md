# mtls

## Responsibilities
- Binds tokens to the client's certificate (RFC 8705), as a binding kind of `sender-binding`.
- Checks the certificate under PKI through its internal module `pki`, or takes it self-signed.

## Not here
- Reading the certificate off a trusted proxy's header: `client-certificate`.
- Authenticating clients by certificate.
- Stamping and checking a token's binding: `tokens`.
- Path validation and revocation rules: `pki`.

## Offers
- Composition definition only. The binding kind: `cnf` member `x5t#S256`, named `mtls` for operators, token type `Bearer`.
- Contribution to `issuer`'s metadata: `tls_client_certificate_bound_access_tokens`.
- Operator section, each value explained in its schema:
  - `mode`: `self-signed`, or `pki` with `anchors`, `max-intermediates` (4), `min-rsa-bits` (2048) and `revocation`.
  - `revocation.mode`: `disabled`, `crl`, `ocsp` or `both`, with `on-unavailable` and `hosts`.
  - `revocation` limits: `nonce` (true), `skew` (`5m`), `ocsp-fresh` (`10m`), `crl-ttl` (`1h`), `failure-lifetime` (`30s`), `crl-entries` (256), `ocsp-entries` (1024), `timeout` (`3s`), `max-fetches` (4); times written with their unit, a bare number refused.

## Invariants
- The binding is the base64url SHA-256 of the leaf's DER, the same at issuance and at a resource.
- A certificate the proxy forwarded unreadable is refused.
- Self-signed: any certificate that parses binds, which every start warns of (`mtls.self_signed`).
- PKI: a path to an anchor whose revocation is confirmed binds; with `revocation.mode = disabled`, any path to an anchor binds, which every start warns of (`mtls.revocation_unchecked`).
- A refusal answers `invalid_client` at issuance, a code RFC 6749 §5.2 registers, and `invalid_token` at a resource (RFC 8705 §3); its reason is only logged.
- An outage answers unavailable under `on-unavailable` reject, and binds with a warning under allow, which every start also warns of (`mtls.binds_during_outage`).
- Boot is refused when `client-certificate` names no form certificates are forwarded in.
- Revocation material is fetched through `outbound.signed`, from the named hosts alone, read as `host-entries` reads a host list (`.name` for the name and the names under it).
- A source failing (5xx), busy (429), timed out (408), or not answering in time and size is an outage.
- A destination not allowed, or any other answer, is a refusal.
- An answer's content is used only after `pki` checks its signature.

## Data
- Revocation caches in the process, held by `pki`'s internal module `revocation`; nothing is stored.

## Depends on
- `kernel`, `client-certificate`, `issuer`, `sender-binding`, `outbound`, `host-entries` (the hosts list read as an operator writes hosts)
