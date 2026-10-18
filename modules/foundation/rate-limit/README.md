# rate-limit

## Responsibilities
- Counts uses in windows on `store`, and locks keys out after failures (backoff, a budget in a window, a hard limit, forgetting a quiet run).

## Not here
- Window numbers, lockout policies and key names: the caller's.

## Offers
- `rateLimit` and `attemptLimit`: count a name and key in a window, answering allowed or limited with a wait; attempts at credentials are counted apart.
- `attemptsPerSource` for routes: by IPv4 address or IPv6 /64; over the limit `429` `too_many_attempts` with `retry-after`; uncounted `503` `service_unavailable`.
- `requestsPerSource` for routes: keyed alike; over the limit `429` `rate_limited`; uncounted, `503` `service_unavailable`, or let through where the section's `fail-mode` is `open` (default `closed`, so a store outage never lifts a limit).
- An undetermined source is logged as a deployment error and answered `503` by both policies.
- `sourceKey` (a source address, in `request-source`'s canonical form): the key both policies count it by, for a route counting in its own handler.
- `lockouts`: check; record a failure; reserve an attempt; end a run on success; hand back an abandoned attempt; tell a release's standing; release, whole or on terms judged as written.
- A reservation is the check and one counted attempt in one write; a held key counts nothing; the reservation that starts a hold says so.
- `lockoutProblem`: why a lockout policy cannot be used, for the caller to refuse boot.
- Audit events: declared in `./audit-events`, listed in the audit event reference; a policy's uncounted request says whether it was refused or let through.
- The counter `auth_rate_limit_uncounted_total` (to `metrics.instruments`): each use `rateLimit` (`limit` `requests`) or `attemptLimit` (`attempts`) could not count, once, whether a policy or a handler counted it.
- A stand-in (`./testing`) counting in memory, with no store or audit, answering alike but never failing.

## Invariants
- A count that cannot be made is unavailable; only the requests policy set `open` then lets a request through. Any other failure is thrown.
- Keys of any length are taken; a name keeps its windows apart.
- A wait is a hint: at least a second, never longer than the window, which the store's clock judges.
- Lockout times are the store's: a hold ends at its time; a fixed hold ends only by release.
- Handing back the attempt that fixed a hold lifts it; handing back any other keeps it.
- Attempt times are unique within a key and never go back, so a reservation names one attempt.
- A success ends the run but keeps failures in the budget; the budget's window is the caller's.
- A lockout that keeps losing races is unavailable; a reservation it cannot hand back stays a failure, the safe side.

## Data
- Limit windows: no eviction, so a flood cannot reset a count; not replicated, as no credential depends on them.
- Attempt windows: no eviction and replicated, so a failover cannot lift a limit on guesses.
- Lockouts: one state per name and key, rewritten whole; no eviction, durable, replicated, and confirmed reads, as a release is read by another request. One that counted a release never expires.

## Depends on
- `kernel`, `store`, `http`, `request-source`, `audit`, `metrics`

## Vocabulary
- window: the period over which counts are made.
