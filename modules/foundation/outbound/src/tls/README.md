# tls

Internal module of `outbound`: the options each TLS connection outbound makes takes.

## Responsibilities
- Makes each TLS connection's options, direct or through the proxy's tunnel: a test's authorities, then the floor given (`tls-options`').

## Not here
- What the floor is, and its section: `tls-options`. Which destinations are reached: `outbound-policy`.

## Offers
- `Tls` (`floor`, `tls-options`' `TlsOptions`; `ca`, a test's authorities) and `tlsOf` (a `Tls`) → the options a connection takes.

## Invariants
- The floor's own keys (`minVersion`, `ciphers`) are copied last, over the test's authorities: nothing a caller passes loosens them, and no other key rides in with them.
- A server offering only what the floor leaves out (an older TLS, the RSA key exchange, CBC) is `unreachable`, directly and through the proxy alike.
