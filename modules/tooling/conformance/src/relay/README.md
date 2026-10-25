# relay

Internal module of `conformance`: a relay between an app and Redis that causes a fault at a known point and shows that it happened.

## Responsibilities
- Reads RESP2 both ways on each connection and pairs each answer with its request, in order, wherever chunks split or join the frames.
- Causes the faults a scene asks for, and records what Redis answered.

## Offers
- `startRelay` (→ its URL, the fault controls, `executions`, `connections`, `close`), on an upstream given, and `upstreamOf` a Redis URL.
- A match: the requests a fault is about, and which of their answers show a write that took effect; the caller gives both.
- Faults: `stall` one way or both, until `resume`; `delay` one way or both; `reset` all connections or those of one role; `dropReplyTo` a match, with its resends where asked, until ended; `hold` a matched request until released; `switchUpstream` for connections opened from then on.
- Observation: `observe` a match until an answer comes out as asked (succeeded or failed); `executions`, each answered request with its connection and time; `connections`, each with its role, upstream and whether open.

## Invariants
- An answer is dropped only where the match says it shows a write; a matched answer showing none is passed on, and the drop fails as no fault having happened.
- A dropped answer cuts its connection both ways, so no later answer is paired with the wrong request; the requests behind it are reported, each with whether Redis had answered it.
- A held request, and every request after it on its connection, reaches Redis only once released; cut, they never do.
- A match on a request inside a transaction (after `MULTI`, until `EXEC` or `DISCARD`) is refused, as `QUEUED` shows nothing ran.
- RESP3, subscriptions, `MONITOR`, inline commands and frames it cannot read cut their connection.
- What it refused, or a fault that did not happen, fails the relay's `close`.
- A connection's role comes from the caller's `roleOf`, read from what the connection sends; the relay holds no store or feature vocabulary.
- Times are on the relay's monotonic clock.

## Depends on
- Node's `net`.
