# transport

Internal module of `outbound`: carrying one request, admitted by the policy, to its destination and its answer back: direct, or through the proxy's tunnel.

## Responsibilities
- Sends the request on the way the internal module `ways` makes, and reads the answer, under one deadline.

## Not here
- Whether a URL and its addresses are admitted, and the limits: `outbound-policy`. How the destination is reached (directly, through the proxy), TLS and the peer's check: `ways`. Counting requests and lookups, reading the section, and warnings at start: the package's. TLS options: `tls`. A credential's header: `credential`.

## Offers
- `send` (the request, the policy's admission and limits, a resolver, a route if a proxy is set, a peer's check, the monotonic time, whether the proxy carries plain http) → the answer, or a refusal or a failure the package throws as unavailable.
- `Resolver`, `Lookup`, `systemLookup` (the system's lookup in this process), `Route` (the proxy, how its name resolves, its authorization, the hosts left direct), `PeerCheck` (`ways`'), and `decided` (the headers outbound alone sets).

## Invariants
- outbound alone sets `User-Agent` (`auth-provider`), `Accept-Encoding`, `Host` and the headers that frame and carry the message.
- A 3xx other than 304 is refused as a redirect; a 101, an encoded answer, a body past the size cap, or headers past Node's 16 KiB are unavailable, and the connection is closed; other 1xx answers are waited past.
- One deadline, the policy's limit, covers resolving (or the tunnel), connecting, the headers and the body; the body is cut at the policy's size.
- The way to the destination, and what holds on it, is `ways`', as its card says.

## Depends on
- `ways`, `outbound-policy` (admission, refusals, limits), `tls`, the package's contract; node's `dns`, `http` and `https`
