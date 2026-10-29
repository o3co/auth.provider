# tls

Internal module of `outbound`: the options each TLS connection outbound makes takes.

## Responsibilities
- Holds every TLS connection, direct or through the proxy's tunnel, to `tls-options`' floor, which outbound takes (`tlsOptions`).

## Not here
- What the floor is, and its section: `tls-options`. Which destinations are reached: `outbound-policy`.

## Offers
- `noteHandshake` (a failure, the error behind it) and `handshakeCodeOf` (a failure): what refused the handshake (its TLS alert, RFC 8446 §6, or an `ERR_SSL_*` code), kept beside the failure, never on it; callers see the failure alone.
- `Tls` (`floor`, required, the `tlsOptions` outbound takes; `ca`, a test's authorities) and `tlsOf` (a `Tls`) → the options a connection takes.

## Invariants
- The floor is one `tls-options` made (`isFloor`), checked once, at `outboundOver`: another, a copy however alike included, throws `NotTheFloor` there, and the module refuses boot at `outbound`, saying to provide it from `@mod/tls-options`.
- The floor's own keys (`minVersion`, `ciphers`) are copied last, over the test's authorities: nothing a caller passes loosens them, and no other key rides in with them.
- A server offering only what the floor leaves out (an older TLS, the RSA key exchange, CBC) is `unreachable`, directly and through the proxy alike.
