# subject-revocation-http

## Responsibilities
- Takes an outside user ledger's revocation of a subject, sent with a credential from a listed source over https, and records it through `subject-revocation`, so the subject's open sessions and tokens stop here too.

## Not here
- What a revocation stops, and its followers: `subject-revocation`'s and theirs.
- Which subject to revoke, and when: the ledger's. Throttling floods: the proxy in front.

## Offers
- `POST /ledger/subject-revocations`, JSON `{ "subject", "delegations"? }`: `delegations` `end` (the default) or `keep`.
- Checked in order, all in the handler: `https` (else `403` `https_required`, the credential unread); the source in `sources` and the credential (`403` `forbidden_source` from outside, whatever the credential; `401` `unauthenticated` with `WWW-Authenticate: Bearer` from inside); the windows; the body (`400` `invalid_request`, its values never echoed).
- `200` `{ "complete": true }`: the boundary is written and every follower finished.
- `503` `temporarily_unavailable` with `Retry-After: 5`: `state` `unknown` (the boundary's write was not confirmed), `incomplete` (written, so everything reading it refuses, but a follower did not finish), or no `state` where a window could not count.
- `429` `rate_limited` with the wait: a source past its failure window (counting `403` and `401` alike), or past its request window (counting authenticated requests).
- Audit events in `./audit-events`: `subject.revocation.requested` (subject, `delegations`, `outcome`, `source`) and `subject.revocation.denied` (`reason`, `source`).
- Operator section: `credential` and `previous-credential` (bare bearer tokens of at least 32 bytes of key material), `sources` (IP addresses or CIDR blocks, at least one), `failures` (10) per `failure-window` (`1m`), `requests` (600) per `window` (`1m`).

## Invariants
- Boot is refused unless http trusts a proxy (`site.proxied`): no request is otherwise told as https.
- https is told by the trusted proxy, where TLS ends; the network between it and the provider must be the operator's own.
- A missing and a wrong credential get the same answer. The current and the previous credential are both compared; the comparison is constant in time only between equal lengths, as a credential's length is no secret.
- An undetermined source is refused, its failures counted under the address of the proxy that sent it, so every request behind that proxy shares one count.
- Windows are keyed by `rate-limit`'s `sourceKey` (an IPv6 source by its /64): failures in `attemptLimit` (replicated), requests in `rateLimit`. The failure window never stops an authenticated request.
- A window that cannot count refuses with `503`, recorded as denied `rate_limit_unavailable`; `rate-limit` counts it in `auth_rate_limit_uncounted_total`, and this module has no metric of its own.
- A subject is one `users` takes (1 to 255 ASCII characters) without control characters, as it goes into store keys and the audit; audit receivers still escape it. Any shaped subject gets `200`, a user or not.
- Recording again is safe and moves the boundary to now: the ledger resends until `200`. A resend that lands after the user is reinstated closes their new sessions, so the ledger cancels pending resends before reinstating.
- Every subject sent keeps a boundary with no end, so the records grow with the subjects the ledger revokes.
- Bodies http answers before the handler (`400` unreadable JSON, `413` too large, `415` not JSON) are neither counted nor recorded.
- `unknown` and `incomplete` are logged as warnings; credentials are never logged or recorded.
- Complete says nothing of what lies outside this provider: an RP told of the logout, or a token handed upstream.
- Left running: an access token unbound to a session where `tokens`' `subject-check` is `none`, a JWT a resource server checks itself, and an upstream token, each until it expires; a request already past its checks when the boundary was written.

## Depends on
- `kernel`, `http`, `keys`, `rate-limit`, `audit`, `request-source`, `users`, `subject-revocation`

## Vocabulary
- boundary: `subject-revocation`'s time before which the subject's sessions and delegations no longer count.
- source: who sent a request, as `request-source` tells it past the trusted proxies.
