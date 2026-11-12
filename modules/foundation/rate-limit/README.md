# rate-limit

## Responsibilities
- Counts uses in windows on `store`, and locks keys out after failures (backoff, a budget in a window, a hard limit, forgetting a quiet run).

## Not here
- Window numbers, lockout policies and key names: the caller's.

## Offers
- `rateLimit` and `attemptLimit`: count a name and key in a window, answering allowed or limited with a wait; attempts at credentials are counted apart.
- `attemptsPerSource` for routes: by IPv4 address or IPv6 /64; over the limit `429` `too_many_attempts` with `retry-after`; uncounted `503` `service_unavailable`.
- `requestsPerSource` for routes: keyed alike; over the limit `429` `rate_limited`; uncounted, `503` `service_unavailable`, or let through where the section's `fail-mode` is `open` (default `closed`, so a store outage never lifts a limit), which every start warns of (`rate-limit.fail_open`).
- Both are marked `per-source` for every method at `http`'s `marks`; the stand-in marks them too.
- An undetermined source is logged as a deployment error and answered `503` by both policies.
- `sourceKey` (a source address, in `request-source`'s canonical form): the key both policies count it by, for a route counting in its own handler.
- `lockouts`: check; record a failure; reserve an attempt; end a run on success; hand back an abandoned attempt; tell a release's standing; release, whole or on terms judged as written, refusing terms that keep their id for no positive whole number of ms.
- A reservation is the check and one counted attempt in one write; a held key counts nothing; the reservation that starts a hold says so.
- `lockoutProblem`: why a lockout policy cannot be used, for the caller to refuse boot.
- `subjectLockouts`: a lockout name whose keys are subject ids, contributed by the module locking by it; a name contributed twice refuses the boot. The eraser `rate-limit` drops a subject's key under each (internal module `drop`); the stand-in contributes it too, declaring no space.
- Audit events: declared in `./audit-events`, listed in the audit event reference; a policy's uncounted request says whether it was refused or let through.
- The counter `auth_rate_limit_uncounted_total` (to `metrics.instruments`): each use `rateLimit` (`limit` `requests`) or `attemptLimit` (`attempts`) could not count, once, whether a policy or a handler counted it.
- A stand-in (`./testing`) counting in memory, with no store or audit, answering alike but never failing.

## Invariants
- A count that cannot be made is unavailable; only the requests policy set `open` then lets a request through. Any other failure is thrown.
- Keys of any length are taken; a name keeps its windows apart, where names hold no line feed (a name and a key are joined by one).
- A wait is a hint: at least a second, or the whole window where it is shorter, and never longer than the window, which the store's clock judges.
- How a lockout holds, counts, hands back and releases, and how its state is kept: internal module `lockout`.
- A dropped key is unavailable at every entry point, `failed` and `releaseUnder` (`whole` included) among them, and none writes it again. Only a request racing its subject's erasure meets one: that 503 is not an outage. A subject id is never issued again, so a key stays dropped for good. Only keys under the names composed at erasure are dropped. A write meeting a dropped key fails closed and writes nothing, so the drop holds whatever eraser runs after.

## Data
- Limit windows: no eviction, so a flood cannot reset a count; not replicated, as no credential depends on them.
- Attempt windows: no eviction and replicated, so a failover cannot lift a limit on guesses.
- Lockouts: one state per name and key, `pseudonymous`, erased by `rate-limit` (internal module `lockout`). A state expires unless its hold is fixed or it counted a release; a dropped key never does.

## Depends on
- `kernel`, `store`, `http`, `http-server` (the policies' rules and marks), `request-source`, `audit`, `metrics`, `erasure-extensions` (the eraser)

## Vocabulary
- window: the period over which counts are made.
- dropped: a lockout key whose subject was erased; it holds nothing else, answers unavailable and is never written again. The eraser's report calls it `forgotten`, erasure-extensions' word.
