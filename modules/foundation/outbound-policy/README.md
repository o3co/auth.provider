# outbound-policy

## Responsibilities
- Owns the destination policy: where an outbound request may go, at which addresses, with what credential, and how far it may run, judged from the operator's settings without sending anything.
- Answers the boot questions a caller asks of it: why a URL is refused and what to set, and where a credential may not go.

## Not here
- Sending, resolving names, connecting, the proxy and the answers: `outbound`, which owns the operator's section `outbound` and applies this policy to every request. What a destination means to a feature: the caller's.

## Offers
- `outbound.refusals`: at boot, why the policy refuses a URL and what to set, `<reason>: <what to set>` (`outbound.allow`, `outbound.plain-loopback`, `outbound.plain-internal`, `outbound.internal-hosts`, `outbound.deny`, or the URL to write otherwise), naming keys alone and never the URL's host, port or other value; nothing when the policy lets it through.
  - It resolves no name and sends nothing, so a caller sending credentials can refuse boot on a destination it could never reach; a name passes on its name, an address in the URL is checked at once. A host the caller's own narrowing leaves out is told as no key to set.
- `destinationRefusal` (the refusals, a URL, a narrowing, what is refused, `it` unless given) → the boot refusal every module gives for it, `outbound's destination policy refuses <what>: <reason>: <what to set>`, or nothing; the words are this package's alone.
- `outbound.credentials`: at boot, why a caller's credential must not go to its URLs (`origins`: more than one; `scheme`: one neither https nor a named `plain-loopback` or `plain-internal` pair), or nothing; `credentialRefusalText` gives either in the words every caller uses.
- `outbound.limits`: at boot, where a request under a narrowing is cut (`timeoutMs`, `maxBytes`): the operator's caps narrowed, never widened, the same limits the sender cuts it at.
- `policySettings`: the keys a section takes for the policy (`allow`, `allow-any-public`, `deny`, `plain-loopback`, `plain-internal`, `internal-hosts`, the size caps and `timeout`); `hostList`: a list of hosts, or `.name` for the name and the names under it.
- `policyOf` (the settings) → the policy: admitting a URL, admitting the addresses it resolved to and answering those checked, explaining a refusal, the credential rule, whether a host is listed, and the limits a request is cut at.
- `hostEntryOf`: an operator's host list entry, as an entry or a narrower's host; `withinHosts`: whether a URL's host is among hosts.

## Invariants
- No host is reached by name unless `allow` names it (`.name` for it and the names under it) or `allow-any-public` is set, never both; `deny` is checked first. An address `deny` names is refused also where a name resolved to it, an IPv4 address carried in IPv6 as the IPv4 one; a name `deny` names is the URL's host alone.
- An `allow` or `deny` entry that is not a host, a `plain-loopback` entry that is not a host and a port written as 1–65535 without a leading zero, or a host list entry that is neither a host nor `.name` is refused. An entry is read as written: letters, digits and hyphens, or a whole address; only case and Unicode are corrected.
- A URL is https, without user information, on no port the Fetch standard calls bad nor port 0. Plain http reaches a named `plain-loopback` pair at loopback addresses alone; signed material also takes it at public addresses, from the caller's hosts only.
- Plain http reaches a pair `plain-internal` names only for the caller's own `internal` URL at its origin, never for an `outsideChosen` one, and only where every address it resolves to is private, by the definition `internal-hosts` uses: a public one among them is `plain-public`, any other `special-address`. `internal-hosts` takes public and private addresses alike; `plain-internal` takes private ones alone. A pair in both plain lists refuses boot.
- Hosts compare lowercase, in punycode, without a trailing dot, in canonical IP form, with IPv4 carried in IPv6 as IPv4; an empty label is denied.
- One special-purpose address refuses them all: IANA's blocks not globally reachable, multicast, and IPv6 outside global unicast. Only an `internal` URL, at a host in `internal-hosts`, reaches private ones: 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, but the cloud metadata addresses in them (100.100.100.200, fd00:ec2::254, fd20:ce::254).
- A caller names `internal` the operator's URL as url-setting read it (a `ConfiguredUrl`, a type nothing else makes) and reaches a private address only at that URL's origin: scheme, host and port. A redirect is never followed, so no other origin is reached.
- A caller narrows the hosts and caps, never widens them; a narrowing's size or time that is not positive and finite is the caller's error. Signed material always names its hosts, none meaning none. A caller whose destinations an outside party chooses marks them `outsideChosen`, for outbound to give their lookups a share apart; `outbound.limits` answers how many a caller may run at once (`lookupsOf`), so one given none can refuse boot.
- A credential goes to one origin alone, over https or to a named `plain-loopback` or `plain-internal` pair: the policy answers this (`outbound.credentials`), and the caller applies it at boot. The sender applies the other two rules: no credential with signed material (`credential`), and no redirect followed (`redirect`).

## Depends on
- `kernel`

## Vocabulary
- destination policy: where requests may go, and how far each may run.
- narrower: what a caller adds for its own requests: fewer hosts, a smaller size, a shorter time, and whether its URL is the operator's own.
