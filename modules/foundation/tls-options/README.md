# tls-options

## Responsibilities
- Owns the floor of the provider's own TLS connections as a client: the least version and the suites they take, and that each checks its peer's certificate.

## Not here
- Trust (`ca`, which authorities are believed): each caller's; that the certificate is checked at all is the floor's. Which destinations may be reached: `outbound-policy`. Ending TLS for the provider's own listeners: the deployment's front.

## Offers
- Composition definition (`./module`), providing `tlsOptions`: the floor (`minVersion`, `ciphers`, `rejectUnauthorized`), as `node:tls` takes it, frozen, from the section.
- `heldToFloor` (the floor, a caller's options) → those options with the floor's own keys copied last, so nothing the caller passes loosens it, whatever keys the floor comes to hold; a value `isFloor` refuses throws a `TypeError`.
- Operator section `tls-options`: `min-version` (`TLSv1.2` (default) or `TLSv1.3`) and `suites` (TLS 1.3's and TLS 1.2's ECDHE with AES-GCM or ChaCha20-Poly1305, every one by default; at least one, each once).
- `isFloor` (a value): whether it is a floor tls-options made, by any copy of the package; a caller refuses any other.
- For tests, `tlsOptionsForTests` (the module, its section left to its defaults), `tlsOptionsFor` (a section as written, read through its schema, made as the module makes it) and `testTlsOptions` (the options the defaults give).
- For tests (`./testing`), each `Offer` a localhost peer offering one thing alone (TLS 1.1, the RSA key exchange, CBC, ECDHE with AEAD on TLS 1.2, or TLS 1.3): `handshakeWith` (a client's options, an offer, and whether the peer's certificate is trusted, by default so) → the version and suite agreed, or refused.
- For tests, `peerOptions` (an offer) → that peer's server options and the authority to trust it, for a server of the caller's own (HTTP, SMTP, Redis) to answer past the handshake. Their certificates are made by `openssl` (on the path) when first asked, and no key is kept in the package.

## Invariants
- The section cannot go below the floor: TLS 1.2 or later; on TLS 1.2, ECDHE with AES-GCM or ChaCha20-Poly1305 alone (BCP 195, RFC 9325 §4), never the RSA key exchange nor CBC. A value outside it refuses boot at its key.
- Each version taken has a suite named: a TLS 1.3 suite always, and a TLS 1.2 suite while `min-version` is `TLSv1.2`; else boot is refused at `suites`, saying which to name. Node, missing one version's suites, would take it with its own or drop it, saying nothing. No `maxVersion`: a later TLS is never cut.
- `TlsOptions` is made only here, from a read section, frozen and marked (`Symbol.for("@mod/tls-options.floor")`, not enumerable): its type is a brand no other package can write, and `isFloor` refuses a copy (a spread, `Object.assign`), a cast or a frozen value written elsewhere.
- The mark stands in until kernel can bind a contract's value to its owner; then the check moves to kernel.
- The peer's certificate is always checked (`rejectUnauthorized`): `NODE_TLS_REJECT_UNAUTHORIZED`, which Node follows only where a connection names nothing, switches no check off, and at `0` every boot warns `tls-options.reject_unauthorized_ignored`, naming the variable alone. A private authority goes in the platform's store (`NODE_EXTRA_CA_CERTS`).
- No setting loosens it below that floor, by decision. One that came to be needed would be an `accept-*` opt-out, warned of at every start.
- A peer's lowered security level (TLS 1.1 needs `@SECLEVEL=0`) stays in `./testing`, which no shipped code imports.

## Depends on
- `kernel`
