# ways

Internal module of `transport`: the way a request reaches its destination: directly at an address checked here, through the proxy's tunnel, or, for plain http the caller asks the proxy to carry, in absolute form to the proxy.

## Responsibilities
- Resolves the destination's name once and connects only to an address the policy checked, or reaches the proxy as the deployment's own; makes TLS to the destination and waits on the peer's check, holding the deadline.

## Not here
- The request and its answer: `transport`. Admission: `outbound-policy`. TLS options: `tls`.

## Offers
- `wayOf` (the admission, a resolver, the policy, the route, TLS, the deadline's signal, the peer's check, the monotonic deadline, whether the proxy carries plain http) → the agent the request goes on, where it goes, and what to let go if it is never made. `PeerCheck`; `failedAs`, `unavailable`, `writtenAddress`.

## Invariants
- Over TLS, direct or tunnelled, the handshake ends and the peer's check, where one is given, is waited on before any byte of the request goes; at the deadline meanwhile, or the connection lost, it ends (`timeout`, `unreachable`).
- After the check, and again as the request is first written, the deadline is asked by the monotonic time `send` is given (the kernel's): past it, the connection ends (`timeout`) with nothing sent, though its timer has not yet fired.
- The time to encode and send that first write is the request's own, bounded by the size of what the caller built. Transport yields once to the timers first, so one held back by the check may fire; that is not what holds the deadline. Without a monotonic time, the deadline's signal alone holds it.
- A `proxy` (an http origin alone, as the URL parser writes it, without credentials; `proxy-authorization` apart) carries every https request, but to `direct-hosts` (list internal hosts there too), by CONNECT with TLS to the destination inside. Then outbound resolves no name but the proxy's own, as one of the deployment's lookups: it checks the name and any address in the URL; the proxy checks where a name resolves. A refused tunnel is `proxy-refused`.
- Plain http, a `plain-loopback` or `plain-internal` pair's, never goes through the proxy: outbound resolves the name and checks every address itself. Signed material the caller asks the proxy to carry (outbound's CRL fetch) goes to it in absolute form (`GET http://…`, the destination its Host, `proxy-authorization` the proxy's alone), but to `direct-hosts`; the proxy resolves and checks the name, outbound only an address the URL writes; the answer is read as any other.
- For plain http taken as such a pair's (signed material too), to a host and port `plain-ipv4` names, the name is resolved to IPv4 addresses alone: every one of those is checked by the policy, the first reached, and an IPv6 one is neither checked nor reached. Other ports of the name, https to it, and plain http not taken as the pair's resolve every family.

## Depends on
- `outbound-policy` (address checks), `tls`, the package's contract (unavailable and its failure), `transport`'s types; node's `http`, `https`, `net` and `tls`
