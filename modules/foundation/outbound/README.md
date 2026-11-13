# outbound

## Responsibilities
- Sends every outbound HTTP request, applying `outbound-policy`'s destination policy to its URL before sending and its addresses before connecting.
- Holds only the counts of requests and lookups running in this process, so it is safe on many instances.

## Not here
- Where a request may go, at which addresses, with what credential, and how far it may run: `outbound-policy`. What a destination means, and which destinations a feature uses: the caller's, in its own section.

## Offers
- `outbound`: fetch a URL with a request and a narrower, answering status, headers and body, or throwing a destination refusal or unavailable with its failure. That unavailable is `OutboundUnavailable`; `isOutboundUnavailable` tells it by its mark, not its class, so a second bundled copy's is told too.
- `outbound.signed` (`signedOutbound`): the same for signed material, with the narrower's hosts always named.
- `credentialHeaderRefusal` (`credential`'s): why a credential may not go as a header named so.
- `DestinationRefused`, `RefusalReason` and `Narrower`, `outbound-policy`'s, as `fetch` throws and takes them. Composition definition, providing `outbound-policy`'s `outbound.refusals` (`plainInternal` and `browsedRefusal` too), `outbound.credentials` and `outbound.limits` from the section.
- A JSON call: `postJson` posts a body as JSON, asking JSON back, its credential under the credential rule below (a Bearer token, or as given in the header named); a send that fails throws what its caller makes of `sendFailureOf`'s kind: the policy's reason, a `failure` (Vocabulary), or `no-answer`. `jsonObjectOf` reads one frozen UTF-8 object, at the status named, `200` by default.
- `./module`: `outboundOver`, the paths over the settings, the lookups and the TLS floor, refusing a floor not tls-options' own (`NotTheFloor`). Operator section `outbound` (`section`): `outbound-policy`'s keys, `max-concurrent`, `max-lookups`, `resolution`, the proxy, `direct-hosts` (a host list, as `host-entries` reads one), `plain-ipv4` and `revocation`; its keys are in the configuration reference.

## Invariants
- Sends every request that leaves the deployment itself, as no other package does (`network`: `outbound`).
- A request goes only to a URL the policy admits; a name is resolved once, as the URL writes it (a trailing dot kept), and the request connects only to the first of the addresses the policy checked, all it resolved to.
- A credential goes only as a request's `credential`, under the internal module `credential`'s rules.
- Internal module `transport` carries each request: direct or through the proxy's tunnel, under one deadline, as its card says. Over TLS, a peer's check ends within the deadline by the kernel's monotonic time; a runtime that gives none (a test's) holds it by the deadline's timer alone, which work in hand may hold back.
- Every TLS connection, direct or through the proxy's tunnel, takes `tls-options`' floor, as the internal module `tls` says.
- Internal module `revocation` checks a TLS peer's revocation by CRL before a request goes, and warns of what is not good; 0.20 sends whatever it finds. With no `revocation.hosts`, none is checked, warned at every start (`outbound.revocation_unchecked`), as is `accept-unconfirmed` (`outbound.revocation_unconfirmed_accepted`).
- A request past `max-concurrent` is unavailable at once, and each request gives its place back however it ends. Name lookups count apart: `max-lookups` at once (four unless set, never more than `max-concurrent`); one more is unavailable at once.
- Names resolve as the system does, hosts file included: by default (`resolution`: `helper`) in helper processes, a helper that does not start refusing boot; with `in-process`, here, no deadline stopping one. See the internal modules `resolver-process` and `lookups`.
- Of those lookups, names a caller marks `outsideChosen` resolve in a pool of their own, its share as `lookups` says, so an outside party's slow names never hold every lookup. `outbound.limits` answers each caller's share (`lookupsOf`), so a caller given none refuses boot.
- A lookup failing is told as a failure: `busy` where no lookup place is free (past `max-lookups` or the caller's share, or a helper not ready), and `unreachable` where it gives no address (the name not found, too many addresses, a helper's fault or its `refusing`, or a stop), or `timeout` at the deadline.
- A `plain-ipv4` entry names, by name and once, a pair `plain-loopback` or `plain-internal` names; else boot is refused, naming neither host nor port.
- Each start warns of each list it is given by the entries' count alone, never a host: `outbound.plain_internal` (what goes to those pairs, passwords, tokens, credentials and keys, is in the clear), `outbound.plain_loopback`, `outbound.plain_ipv4`, `outbound.internal_hosts`.
- Each start warns, by a reason alone: `outbound.any_public_host` (`allow-any-public`); `outbound.resolution_in_process`; `outbound.proxy_checks_addresses` (a `proxy`); and `outbound.proxy_credentials_in_clear` where `proxy-authorization` goes to a proxy not a loopback address written as one (judged as written).
- List in `plain-internal` only peers on a network trusted against reading and changing what passes, such as one task, a closed cluster network or a service mesh; where possible, use https with an internal CA and `internal-hosts` instead.
- Proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, either case) are never read; with one set and no `proxy`, boot is refused, naming the variable alone, unless `direct-despite-proxy` is set.

## Depends on
- `kernel`, `tls-options` (the TLS floor), `outbound-policy`, `x509-path` (through `revocation`), `host-entries` (also `hostPair`, `hostEntryOf` and `withinHosts`, to read and compare `plain-ipv4`'s pairs), `address-reach` (`isLoopbackAddress`), `url-setting` (the proxy's origin)

## Vocabulary
- failure: why outbound is unavailable, for a caller to log by, with no value and no body: `timeout` (the deadline came), `too-large` (a body or headers past the cap), `unreachable` (no address, no connection, or the connection lost), `unsupported-answer` (a 101 or an encoded answer), `busy` (past `max-concurrent`), `proxy-refused`.
