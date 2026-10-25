# conformance-tunnel

## Responsibilities
- Gives a harness's app a way out to a party on this machine that it may reach over https by its name alone: an HTTP CONNECT proxy on loopback, set as the app's `outbound.proxy`.

## Not here
- What the app may reach and how it checks the party's certificate: `outbound`'s, unchanged; the app's TLS runs inside the tunnel.
- Starting the app or the party (the harness's).

## Offers
- `startTunnel({ allow })`: a CONNECT proxy on a port of loopback it takes; `allow` maps each destination, `host:port` as the app names it, to where it listens. Its `opened()` lists the destinations it opened, in order; `stop()` closes every tunnel and the proxy.

## Invariants
- A tunnel opens only to a destination `allow` names; any other is `403`, any method but CONNECT `405`, and a destination that cannot be reached `502`.
- Bytes are carried as they come, both ways: the tunnel neither ends TLS nor reads what it carries.

## Depends on
- No workspace package.
