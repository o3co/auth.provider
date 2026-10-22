# outbound

## Responsibilities
- Offers the only path for outbound HTTP requests, under the operator's destination policy.
- Applies `outbound-policy`'s destination policy to every request, its URL before sending and its addresses before connecting, and cuts each at the limits it answers; holds requests to `max-concurrent`.
- Holds only the counts of requests and lookups running in this process, so it is safe on many instances.

## Not here
- Where a request may go, at which addresses, with what credential, and how far it may run: `outbound-policy`. What a destination means, and which destinations a feature uses: the caller's, in its own section.

## Offers
- `outbound`: fetch a URL with a request and a narrower, answering status, headers and body, or throwing a destination refusal or unavailable with its failure. `isOutboundUnavailable` tells that unavailable by its mark, not its class, so a second bundled copy's is told too.
- `outbound.signed`: the same for signed material, with the narrower's hosts always named.
- `DestinationRefused`, `RefusalReason` and `Narrower`, `outbound-policy`'s, as `fetch` throws and takes them. Composition definition, providing `outbound-policy`'s `outbound.refusals` (`plainInternal` and `browsedRefusal` too), `outbound.credentials` and `outbound.limits` from the section; reading an answer as JSON (one frozen UTF-8 object, at the status named, `200` by default).
- Operator section `outbound`: `outbound-policy`'s keys, `max-concurrent`, the proxy, `direct-hosts` (a host list, as `outbound-policy` reads one) and `plain-ipv4`; its keys are in the configuration reference.

## Invariants
- Sends every request that leaves the deployment itself, as no other package does (`network`: `outbound`).
- A request goes only to a URL the policy admits; a name is resolved once, and the request connects only to the first of the addresses the policy checked, all it resolved to.
- outbound alone sets `User-Agent` (`auth-provider`), `Accept-Encoding`, `Host` and the headers that frame and carry the message.
- An `Authorization` value goes only as a request's `credential`, sent as that header and never told: never for signed material (`credential`), and only as one printable line; an `Authorization` header a caller writes, in any case, is the caller's TypeError. A redirect never carries it, being refused.
- A 3xx other than 304 is refused as a redirect; a 101, an encoded answer, a body past the size cap, or headers past Node's 16 KiB are unavailable, and the connection is closed; other 1xx answers are waited past.
- One deadline, the policy's limit, covers resolving (or the tunnel), connecting, the headers and the body; the body is cut at the policy's size.
- A request past `max-concurrent` is unavailable at once, and each request gives its place back however it ends. Name lookups, which no deadline stops and which run on Node's threadpool, count apart: at most half the threadpool at once (`UV_THREADPOOL_SIZE`, 4 unless set), at least one and never more than `max-concurrent`, so names that answer slowly never hold all of it; one more is unavailable at once. Names resolve as the system does, hosts file included.
- Of those lookups, names a caller marks `outsideChosen` take half at most, rounded down, and the deployment's own the rest, so an outside party's slow names never hold every lookup; with a threadpool of 2 or less they take none. `outbound.limits` answers each caller's share (`lookupsOf`), so a caller given none refuses boot. A name already resolving answers everyone asking it, taking one place.
- A `proxy` (an http origin alone, as the URL parser writes it, without credentials; `proxy-authorization` apart) carries every https request, but to `direct-hosts` (list internal hosts there too), by CONNECT with TLS to the destination inside. Then outbound resolves no name: it checks the name and any address in the URL; the proxy checks where a name resolves (boot warns so). A refused tunnel is `proxy-refused`.
- Boot warns that `proxy-authorization` goes in the clear unless the proxy is a loopback address written as one (`address-reach`'s `isLoopbackAddress`): its name is never resolved here.
- Plain http, a `plain-loopback` or `plain-internal` pair's, never goes through the proxy: outbound resolves the name and checks every address itself, a `plain-loopback` pair's by `isLoopbackAddress`.
- For plain http taken as such a pair's (signed material too), to a host and port `plain-ipv4` names (hosts compared as the policy's lists compare them), the name is resolved to IPv4 addresses alone: every one of those is checked by the policy, the first reached, and an IPv6 one is neither checked nor reached. Other ports of the name, https to it, and plain http not taken as the pair's resolve every family.
- A lookup for IPv4 alone shares no answer with one for every family of the same name and takes a place of its own, so lookups may be busy otherwise than before.
- A `plain-ipv4` entry names, by name and once, a pair `plain-loopback` or `plain-internal` names; else boot is refused, naming neither host nor port.
- Each boot that names `plain-internal` pairs warns `outbound.plain_internal`, with their count alone: what goes to them, passwords, tokens, credentials and keys, is in the clear.
- List in `plain-internal` only peers on a network trusted against reading and changing what passes, such as one task, a closed cluster network or a service mesh; where possible, use https with an internal CA and `internal-hosts` instead. ECS Service Connect writes each name in the hosts file with an IPv4 address and an IPv6 one, which in the environment reported does not reach: name its pair in `plain-ipv4` too.
- Proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, either case) are never read; with one set and no `proxy`, boot is refused, naming the variable alone, unless `direct-despite-proxy` is set.

## Depends on
- `kernel`, `outbound-policy` (also `withinHosts`, to compare `plain-ipv4`'s hosts), `address-reach` (`isLoopbackAddress`), `url-setting` (the proxy's origin)

## Vocabulary
- failure: why outbound is unavailable, for a caller to log by, with no value and no body: `timeout` (the deadline came), `too-large` (a body or headers past the cap), `unreachable` (no address, no connection, or the connection lost), `unsupported-answer` (a 101 or an encoded answer), `busy` (past `max-concurrent`), `proxy-refused`.
