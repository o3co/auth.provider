# transport

Internal module of `outbound`: carrying one request, admitted by the policy, to its destination and its answer back: direct, or through the proxy's tunnel.

## Responsibilities
- Resolves the destination's name once, connects only to an address the policy checked (or tunnels through the proxy), sends the request, and reads the answer under one deadline.

## Not here
- Whether a URL and its addresses are admitted, and the limits: `outbound-policy`. Counting requests and lookups, reading the section, and warnings at start: the package's. TLS options: `tls`. A credential's header: `credential`.

## Offers
- `send` (the request, the policy's admission and limits, a resolver, a route if a proxy is set) → the answer, or a refusal or a failure the package throws as unavailable.
- `Resolver`, `Lookup`, `systemLookup` (the system's lookup in this process), `Route` (the proxy, how its name resolves, its authorization, the hosts left direct), and `decided` (the headers outbound alone sets).

## Invariants
- outbound alone sets `User-Agent` (`auth-provider`), `Accept-Encoding`, `Host` and the headers that frame and carry the message.
- A 3xx other than 304 is refused as a redirect; a 101, an encoded answer, a body past the size cap, or headers past Node's 16 KiB are unavailable, and the connection is closed; other 1xx answers are waited past.
- One deadline, the policy's limit, covers resolving (or the tunnel), connecting, the headers and the body; the body is cut at the policy's size.
- Over TLS, direct or tunnelled, the handshake ends and the peer's check, where one is given, is waited on before any byte of the request goes; at the deadline meanwhile, or the connection lost, it ends (`timeout`, `unreachable`).
- After the check, the deadline is asked by the monotonic time `send` is given (the kernel's): past it, the connection ends (`timeout`) with nothing sent, though its timer has not yet fired. Transport yields once to the timers first, so one held back by the check may fire; that is not what holds the deadline. Without a monotonic time, the deadline's signal alone holds it.
- A `proxy` (an http origin alone, as the URL parser writes it, without credentials; `proxy-authorization` apart) carries every https request, but to `direct-hosts` (list internal hosts there too), by CONNECT with TLS to the destination inside. Then outbound resolves no name but the proxy's own, as one of the deployment's lookups: it checks the name and any address in the URL; the proxy checks where a name resolves. A refused tunnel is `proxy-refused`.
- Plain http, a `plain-loopback` or `plain-internal` pair's, never goes through the proxy: outbound resolves the name and checks every address itself.
- For plain http taken as such a pair's (signed material too), to a host and port `plain-ipv4` names, the name is resolved to IPv4 addresses alone: every one of those is checked by the policy, the first reached, and an IPv6 one is neither checked nor reached. Other ports of the name, https to it, and plain http not taken as the pair's resolve every family.

## Depends on
- `outbound-policy` (admission, refusals, limits), `tls`, the package's contract (unavailable and its failure); node's `dns`, `http`, `https`, `net` and `tls`
