# crl-fetch

## Responsibilities
- Fetches a CRL for a peer's revocation check, as signed material, within the request it is for.

## Not here
- What CRLs are fetched, when, and what they say: `revocation`. Admission and limits: `outbound-policy`. Carrying the request: `transport`. Places: the package's.

## Offers
- `crlFetchOf` (the CRL hosts, the policy, the route, a resolver, TLS, the deadline's maker) → a fetch of a URL under a signal: the CRL's bytes, or `refused`, `proxy-refused`, `unreachable`, `too-large`, or `aborted` where that signal ended it.

## Invariants
- As signed material: plain http at the hosts listed and public addresses alone, no redirect, 1 MiB and 5 seconds at most, or the request's own deadline where it comes first.
- In the place of the request it is for, never one of its own: one request at a time still fetches.
- Names resolve in the outside party's pool, as a certificate chose the URL.
- Through `outbound.proxy` where one is set, but to `direct-hosts`: as plain http in absolute form, the proxy resolving and checking the name. A 403, 405 or 407 from it is `proxy-refused`: the proxy, or rarely the CRL host behind it, refused. Let the proxy take plain-http GET to the hosts in `outbound.revocation.hosts`, or list them in `direct-hosts`.
- A server failing (5xx), busy (429) or timed out (408), or no answer: `unreachable`; any other answer, or a destination refused: `refused`.

## Depends on
- `outbound-policy` (admission, limits), `transport` (`send`), `tls`, `revocation` (the fetch's answer), the package's contract
