# tls-options

## Responsibilities
- Owns the floor of the provider's own TLS connections as a client: the least version and the suites they take.

## Not here
- Trust (`ca`, which certificates are believed): each caller's. Which destinations may be reached: `outbound-policy`. Ending TLS for the provider's own listeners: the deployment's front.

## Offers
- Composition definition (`./module`), providing `tlsOptions`: `minVersion` and `ciphers`, as `node:tls` takes them, frozen, from the section. Spread last over a connection's own options (`{ ...trust, ...tlsOptions }`), so nothing a caller passes loosens it.
- Operator section `tls-options`: `min-version` (`TLSv1.2` (default) or `TLSv1.3`) and `suites` (TLS 1.3's and TLS 1.2's ECDHE with AES-GCM or ChaCha20-Poly1305, every one by default; at least one).
- For tests, `tlsOptionsForTests` (the module, its section left to its defaults) and `testTlsOptions` (the options those defaults give).
- For tests (`./testing`), each `Offer` a localhost peer offering one thing alone (TLS 1.1, the RSA key exchange, CBC, ECDHE with AEAD on TLS 1.2, or TLS 1.3): `handshakeWith` (a client's options, an offer) → the version and suite agreed, or refused.
- For tests, `peerOptions` (an offer) → that peer's server options and the authority to trust it, for a server of the caller's own (HTTP, SMTP, Redis) to answer past the handshake. Their certificates are made by `openssl` (on the path) when first asked, and no key is kept in the package.

## Invariants
- The section cannot go below the floor: TLS 1.2 or later; on TLS 1.2, ECDHE with AES-GCM or ChaCha20-Poly1305 alone (BCP 195, RFC 9325 §4), never the RSA key exchange nor CBC. A value outside it, or `TLSv1.3` with no TLS 1.3 suite, refuses boot at its key.
- TLS 1.3's suites are named, as Node takes TLS 1.3 only where `ciphers` names one. No `maxVersion`: a later TLS is never cut.
- No setting loosens it below that floor, by decision. One that came to be needed would be an `accept-*` opt-out, warned of at every start.
- A peer's lowered security level (TLS 1.1 needs `@SECLEVEL=0`) stays in `./testing`, which no shipped code imports.

## Depends on
- `kernel`
