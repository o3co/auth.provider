# outbound

## Responsibilities
- Sends every outbound HTTP request, applying `outbound-policy`'s destination policy to its URL before sending and its addresses before connecting.
- Holds only the counts of requests and lookups running in this process, so it is safe on many instances.

## Not here
- Where a request may go, at which addresses, with what credential, and how far it may run: `outbound-policy`. What a destination means, and which destinations a feature uses: the caller's, in its own section.

## Offers
- `outbound`: fetch a URL with a request and a narrower, answering status, headers and body, or throwing a destination refusal or unavailable with its failure. `isOutboundUnavailable` tells that unavailable by its mark, not its class, so a second bundled copy's is told too.
- `outbound.signed`: the same for signed material, with the narrower's hosts always named.
- `credentialHeaderRefusal` (`credential`'s): why a credential may not go as a header named so.
- `DestinationRefused`, `RefusalReason` and `Narrower`, `outbound-policy`'s, as `fetch` throws and takes them. Composition definition, providing `outbound-policy`'s `outbound.refusals`, `outbound.credentials` and `outbound.limits` from the section.
- A JSON call: `postJson` posts a body as JSON, asking JSON back, its credential under the credential rule below (a Bearer token, or as given in the header named); a send that fails throws what its caller makes of `sendFailureOf`'s kind: the policy's reason, a `failure` (Vocabulary), or `no-answer`. `jsonObjectOf` reads one frozen UTF-8 object, at the status named, `200` by default.
- Operator section `outbound`: `outbound-policy`'s keys, `max-concurrent`, `max-lookups`, `resolution`, the proxy, `direct-hosts` (a host list, as `host-entries` reads one) and `plain-ipv4`; its keys are in the configuration reference.

## Invariants
- Sends every request that leaves the deployment itself, as no other package does (`network`: `outbound`).
- A request goes only to a URL the policy admits; a name is resolved once, as the URL writes it (a trailing dot kept), and the request connects only to the first of the addresses the policy checked, all it resolved to.
- outbound alone sets `User-Agent` (`auth-provider`), `Accept-Encoding`, `Host` and the headers that frame and carry the message.
- A credential goes only as a request's `credential`, under the internal module `credential`'s rules.
- A 3xx other than 304 is refused as a redirect; a 101, an encoded answer, a body past the size cap, or headers past Node's 16 KiB are unavailable, and the connection is closed; other 1xx answers are waited past.
- Every TLS connection, direct or through the proxy's tunnel, takes `tls-options`' floor, as the internal module `tls` says.
- One deadline, the policy's limit, covers resolving (or the tunnel), connecting, the headers and the body; the body is cut at the policy's size.
- A request past `max-concurrent` is unavailable at once, and each request gives its place back however it ends. Name lookups count apart: `max-lookups` at once (four unless set, never more than `max-concurrent`); one more is unavailable at once.
- Names resolve as the system does, hosts file included: by default (`resolution`: `helper`) in helper processes, a helper that does not start refusing boot; with `in-process`, here, no deadline stopping one. See the internal modules `resolver-process` and `lookups`.
- Of those lookups, names a caller marks `outsideChosen` resolve in a pool of their own, its share as `lookups` says, so an outside party's slow names never hold every lookup. `outbound.limits` answers each caller's share (`lookupsOf`), so a caller given none refuses boot.
- A `proxy` (an http origin alone, as the URL parser writes it, without credentials; `proxy-authorization` apart) carries every https request, but to `direct-hosts` (list internal hosts there too), by CONNECT with TLS to the destination inside. Then outbound resolves no name but the proxy's own, as one of the deployment's lookups: it checks the name and any address in the URL; the proxy checks where a name resolves. A refused tunnel is `proxy-refused`.
- Plain http, a `plain-loopback` or `plain-internal` pair's, never goes through the proxy: outbound resolves the name and checks every address itself, a `plain-loopback` pair's by `isLoopbackAddress`.
- For plain http taken as such a pair's (signed material too), to a host and port `plain-ipv4` names, the name is resolved to IPv4 addresses alone: every one of those is checked by the policy, the first reached, and an IPv6 one is neither checked nor reached. Other ports of the name, https to it, and plain http not taken as the pair's resolve every family.
- A `plain-ipv4` entry names, by name and once, a pair `plain-loopback` or `plain-internal` names; else boot is refused, naming neither host nor port.
- Each start warns of each list it is given by the entries' count alone, never a host: `outbound.plain_internal` (what goes to those pairs, passwords, tokens, credentials and keys, is in the clear), `outbound.plain_loopback`, `outbound.plain_ipv4`, `outbound.internal_hosts`.
- Each start warns, by a reason alone: `outbound.any_public_host` (`allow-any-public`); `outbound.resolution_in_process`; `outbound.proxy_checks_addresses` (a `proxy`); and `outbound.proxy_credentials_in_clear` where `proxy-authorization` goes to a proxy not a loopback address written as one (judged as written).
- List in `plain-internal` only peers on a network trusted against reading and changing what passes, such as one task, a closed cluster network or a service mesh; where possible, use https with an internal CA and `internal-hosts` instead.
- Proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, either case) are never read; with one set and no `proxy`, boot is refused, naming the variable alone, unless `direct-despite-proxy` is set.

## Depends on
- `kernel`, `tls-options` (the TLS floor), `outbound-policy`, `host-entries` (also `hostEntryOf` and `withinHosts`, to read and compare `plain-ipv4`'s pairs), `address-reach` (`isLoopbackAddress`), `url-setting` (the proxy's origin)

## Vocabulary
- failure: why outbound is unavailable, for a caller to log by, with no value and no body: `timeout` (the deadline came), `too-large` (a body or headers past the cap), `unreachable` (no address, no connection, or the connection lost), `unsupported-answer` (a 101 or an encoded answer), `busy` (past `max-concurrent`), `proxy-refused`.
