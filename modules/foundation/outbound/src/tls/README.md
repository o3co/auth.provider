# tls

Internal module of `outbound`: the options each TLS connection outbound makes takes.

## Responsibilities
- Holds every TLS connection, direct or through the proxy's tunnel, to `tls-options`' floor.

## Not here
- What the floor is, and its section: `tls-options`. Which destinations are reached: `outbound-policy`.

## Offers
- `Tls` (`floor`, the `tlsOptions` the module takes; `ca`, a test's authorities) and `tlsOf` (a `Tls`) → the options a connection spreads.

## Invariants
- The floor is spread last, over the test's authorities: nothing a caller passes loosens it.
- A server offering only what the floor leaves out (an older TLS, the RSA key exchange, CBC) is `unreachable`, directly and through the proxy alike.
