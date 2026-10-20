# outbound

## Responsibilities
- Offers the only path for outbound HTTP requests, under the operator's destination policy.
- Applies `outbound-policy`'s destination policy to every request, its URL before sending and its addresses before connecting, and cuts each at the limits it answers; holds requests to `max-concurrent`.
- Holds only the counts of requests and lookups running in this process, so it is safe on many instances.

## Not here
- Where a request may go, at which addresses, with what credential, and how far it may run: `outbound-policy`. What a destination means, and which destinations a feature uses: the caller's, in its own section.

## Offers
- `outbound`: fetch a URL with a request and a narrower, answering status, headers and body, or throwing a destination refusal or unavailable with its failure.
- `outbound.signed`: the same for signed material, with the narrower's hosts always named.
- `DestinationRefused`, `RefusalReason` and `Narrower`, `outbound-policy`'s, as `fetch` throws and takes them. Composition definition, providing `outbound-policy`'s `outbound.refusals`, `outbound.credentials` and `outbound.limits` from the section; reading an answer as JSON (one frozen UTF-8 object, at the status named, `200` by default).
- Operator section `outbound`: `outbound-policy`'s keys, `max-concurrent`, the proxy and `direct-hosts` (a host list, as `outbound-policy` reads one); its keys are in the configuration reference.

## Invariants
- Sends every request that leaves the deployment itself, as no other package does (`network`: `outbound`).
- A request goes only to a URL the policy admits; a name is resolved once, and the request connects only to the first of the addresses the policy checked, all it resolved to.
- outbound alone sets `User-Agent` (`auth-provider`), `Accept-Encoding`, `Host` and the headers that frame and carry the message.
- An `Authorization` value goes only as a request's `credential`, sent as that header and never told: never for signed material (`credential`), and only as one printable line; an `Authorization` header a caller writes, in any case, is the caller's TypeError. A redirect never carries it, being refused.
- A 3xx other than 304 is refused as a redirect; a 101, an encoded answer, a body past the size cap, or headers past Node's 16 KiB are unavailable, and the connection is closed; other 1xx answers are waited past.
- One deadline, the policy's limit, covers resolving (or the tunnel), connecting, the headers and the body; the body is cut at the policy's size.
- A request past `max-concurrent` is unavailable at once, and each request gives its place back however it ends. Name lookups, which no deadline stops and which run on Node's threadpool, count apart: at most half the threadpool at once (`UV_THREADPOOL_SIZE`, 4 unless set), at least one and never more than `max-concurrent`, so names that answer slowly never hold all of it; one more is unavailable at once. Names resolve as the system does, hosts file included.
- Of those lookups, names a caller marks `outsideChosen` take half at most, rounded down, and the deployment's own the rest, so an outside party's slow names never hold every lookup; with a threadpool of 2 or less they take none, so `clients-cimd` needs 4 or more. A name already resolving answers everyone asking it, taking one place.
- A `proxy` (an http origin alone, as the URL parser writes it, without credentials; `proxy-authorization` apart) carries every https request, but to `direct-hosts` (list internal hosts there too) and plain-loopback pairs, by CONNECT with TLS to the destination inside. Then outbound resolves no name: it checks the name and any address in the URL; the proxy checks where a name resolves (boot warns so, and of credentials sent over http past the loopback). A refused tunnel is `proxy-refused`.
- Proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, either case) are never read; with one set and no `proxy`, boot is refused, naming the variable alone, unless `direct-despite-proxy` is set.

## Depends on
- `kernel`, `outbound-policy`, `url-setting` (the proxy's origin)

## Vocabulary
- failure: why outbound is unavailable, for a caller to log by, with no value and no body: `timeout` (the deadline came), `too-large` (a body or headers past the cap), `unreachable` (no address, no connection, or the connection lost), `unsupported-answer` (a 101 or an encoded answer), `busy` (past `max-concurrent`), `proxy-refused`.
