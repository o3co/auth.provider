# outbound

## Responsibilities
- Offers the only path for outbound HTTP requests, under the operator's destination policy.
- Checks a destination before sending and its addresses before connecting, and limits each request's size, time and concurrency.
- Holds only the counts of requests and lookups running in this process, so it is safe on many instances.

## Not here
- What a destination means, and which destinations a feature uses: the caller's, in its own section.

## Offers
- `outbound`: fetch a URL with a request and a narrower, answering status, headers and body, or throwing a destination refusal or unavailable with its failure.
- `outbound.signed`: the same for signed material, with the narrower's hosts always named.
- `outbound.policy`: at boot, why the destination policy refuses a URL, or nothing. It resolves no name and sends nothing, so a caller sending credentials can refuse boot on a destination it could never reach; a name passes on its name, an address in the URL is checked at once.
- Composition definition; reading an answer as JSON (one frozen UTF-8 object, at the status named, `200` by default); whether a URL's host is among hosts; reading an operator's host list, as entries or as a narrower's hosts.
- Operator section `outbound`: the policy, the caps, the proxy and `internal-hosts`; its keys are in the configuration reference.

## Invariants
- No host is reached by name unless `allow` names it (`.name` for it and the names under it) or `allow-any-public` is set; `deny` is checked first.
- Boot is refused on an `allow` or `deny` entry that is not a host, a `plain-loopback` entry that is not a host and a port written as 1–65535 without a leading zero, or a `direct-hosts` or `internal-hosts` entry that is neither a host nor `.name`, for the name and the names under it. An entry is read as written: letters, digits and hyphens, or a whole address; only case and Unicode are corrected.
- A URL is https, without user information, on no port the Fetch standard calls bad nor port 0. Plain http reaches a named `plain-loopback` pair at loopback addresses alone; signed material also takes it at public addresses, from the caller's hosts only.
- Hosts compare lowercase, in punycode, without a trailing dot, in canonical IP form, with IPv4 carried in IPv6 as IPv4; an empty label is denied.
- A name is resolved once, and the request connects only to an address checked among all it resolved to.
- One special-purpose address refuses them all: IANA's blocks not globally reachable, multicast, and IPv6 outside global unicast. Only an `internal` URL, at a host in `internal-hosts`, reaches private ones: 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, but the cloud metadata addresses in them (100.100.100.200, fd00:ec2::254, fd20:ce::254).
- outbound alone sets `User-Agent` (`auth-provider`), `Accept-Encoding`, `Host` and the headers that frame and carry the message.
- A 3xx other than 304 is refused as a redirect; a 101, an encoded answer, a body past the size cap, or headers past Node's 16 KiB are unavailable, and the connection is closed; other 1xx answers are waited past.
- A caller narrows the policy and caps, never widens them; a narrower's size or time that is not positive and finite is thrown as the caller's error. One deadline covers resolving (or the tunnel), connecting, the headers and the body.
- A request past `max-concurrent` is unavailable at once, and each request gives its place back however it ends. Name lookups, which no deadline stops, count apart under the same limit; names resolve as the system does, hosts file included.
- A `proxy` (an http origin without credentials; `proxy-authorization` apart) carries every https request, but to `direct-hosts` (list internal hosts there too) and plain-loopback pairs, by CONNECT with TLS to the destination inside. Then outbound resolves no name: it checks the name and any address in the URL; the proxy checks where a name resolves (boot warns so, and of credentials sent over http past the loopback). A refused tunnel is `proxy-refused`.
- A caller names its URL `internal` only when operator configuration gave it, never a client's, a document's or an answer's; outbound cannot tell.
- Proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, either case) are never read; with one set and no `proxy`, boot is refused, naming the variable alone, unless `direct-despite-proxy` is set.

## Depends on
- `kernel`

## Vocabulary
- destination policy: where requests may go, and how far each may run.
- narrower: what a caller adds for its own requests: fewer hosts, a smaller size, a shorter time, and whether its URL is the operator's own.
- failure: why outbound is unavailable, for a caller to log by, with no value and no body: `timeout` (the deadline came), `too-large` (a body or headers past the cap), `unreachable` (no address, no connection, or the connection lost), `unsupported-answer` (a 101 or an encoded answer), `busy` (past `max-concurrent`), `proxy-refused`.
