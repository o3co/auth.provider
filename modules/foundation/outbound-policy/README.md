# outbound-policy

## Responsibilities
- Owns the destination policy: where an outbound request may go, at which addresses, with what credential, and how far it may run, judged from the operator's settings without sending anything.
- Answers the boot questions a caller asks of it: why a URL is refused and what to set, and where a credential may not go.

## Not here
- How an entry and a pair are read, and whether a host is among such entries or a caller's hosts: `host-entries`, which every module reading hosts takes.
- Sending, resolving names, connecting, the proxy and the answers: `outbound`, which owns the operator's section `outbound` and applies this policy to every request. What a destination means to a feature: the caller's.

## Offers
- `outbound.refusals`: at boot, why the policy refuses a URL and what to set, `<reason>: <what to set>` (the `outbound` destination keys `policySettings` takes, `outbound.plain-ipv4`, or the URL to write otherwise), naming keys alone and never the URL's host, port or other value; nothing when the policy lets it through.
  - It resolves no name and sends nothing, so a caller sending credentials can refuse boot on a destination it could never reach; a name passes on its name, an address in the URL is checked at once. A host the caller's own narrowing leaves out is told as no key to set.
  - Its `plainInternal`: whether a URL is taken as plain http to a `plain-internal` pair for the caller's own `internal` URL; absent, it is read as no.
  - Its `browsedRefusal`: why a URL the browser is sent to is refused: plain http other than at a loopback name or as `plainInternal` takes it; absent, plain http is refused.
- `destinationRefusal` (the refusals, a URL, a narrowing, what is refused, `it` unless given) → the boot refusal every module gives for it, `outbound's destination policy refuses <what>: <reason>: <what to set>`, or nothing; the words are this package's alone.
- `browsedRefusalText` (the refusals, a URL the browser goes to, a narrowing, what), the same for `browsedRefusal`: `outbound's policy for what the browser goes to refuses <what>: …`, https alone where it is absent.
- `outbound.credentials`: at boot, why a caller's credential must not go to its URLs (`origins`: more than one; `scheme`: one neither https nor a named `plain-loopback` or `plain-internal` pair), or nothing; `credentialRefusalText` gives either in the words every caller uses.
- `outbound.limits`: at boot, where a request under a narrowing is cut (`timeoutMs`, `maxBytes`): the operator's caps narrowed, never widened, the same limits the sender cuts it at.
- `policySettings`: the keys a section takes for the policy (`allow`, `allow-any-public`, `deny`, `plain-loopback`, `plain-internal`, `internal-hosts`, the size caps and `timeout`).
- `policyOf` (the settings) → the policy: admitting a URL, admitting the addresses it resolved to and answering those checked, explaining a refusal, the credential rule, whether a host is listed, and the limits a request is cut at.
- `DestinationRefused` (`reason`); `DestinationRefused.is` tells one by its mark, even bundled twice.

## Invariants
- No host is reached by name unless `allow` names it (`.name` for it and the names under it) or `allow-any-public` is set, never both; `deny` is checked first. An address `deny` names is refused also where a name resolved to it, an IPv4 address carried in IPv6 as the IPv4 one; a name `deny` names is the URL's host alone.
- An `allow` or `deny` entry that is not a host, a `plain-loopback` or `plain-internal` entry that is not a pair, or a host list entry that is neither a host nor `.name`, each as `host-entries` reads it, is refused.
- A URL is https, without user information, on no port the Fetch standard calls bad nor port 0. Plain http reaches a named `plain-loopback` pair at loopback addresses alone, as `address-reach`'s `isLoopbackAddress` judges them; signed material also takes it at public addresses, from the caller's hosts only.
- Plain http reaches a pair `plain-internal` names only for the caller's own `internal` URL at its origin, never for an `outsideChosen` one, and only where every address it resolves to is private or loopback, private by the definition `internal-hosts` uses: a public one among them is `plain-public`, any other `special-address`. `internal-hosts` takes public and private addresses alike; `plain-internal` takes private and loopback ones alone. A pair in both plain lists refuses boot.
- Hosts compare as `host-entries` spells them, and a URL whose host has no spelling (an empty label) is `denied`. The lists alone use that spelling: an address in the URL is reached as written (`Admitted.address`).
- One special-purpose address refuses them all. Only an `internal` URL reaches private ones, at a host in `internal-hosts` or over plain http at a `plain-internal` pair. Which addresses are special-purpose, private or loopback is `address-reach`'s.
- A caller names `internal` the operator's URL as url-setting read it (a `ConfiguredUrl`, a type nothing else makes) and reaches a private address only at that URL's origin: scheme, host and port. A redirect is never followed, so no other origin is reached.
- A caller narrows the hosts and caps, never widens them; a narrowing's size or time that is not positive and finite is the caller's error. Signed material always names its hosts, none meaning none. A caller whose destinations an outside party chooses marks them `outsideChosen`, for outbound to give their lookups a share apart; `outbound.limits` answers how many a caller may run at once (`lookupsOf`), so one given none can refuse boot.
- A credential goes only where `outbound.credentials` lets it, which the caller applies at boot. The sender applies the other two rules: no credential with signed material (`credential`), and no redirect followed (`redirect`).

## Depends on
- `kernel`; `address-reach` (special-purpose, private and loopback addresses); `host-entries` (how hosts and pairs are read and compared); `url-setting` (`ConfiguredUrl`)

## Vocabulary
- destination policy: where requests may go, and how far each may run.
- narrower: what a caller adds for its own requests: fewer hosts, a smaller size, a shorter time, and whether its URL is the operator's own.
