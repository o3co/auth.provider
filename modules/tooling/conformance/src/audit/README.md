# audit

Internal module of `conformance`: the events a running target sends, for the scenes that read them.

## Responsibilities
- Runs the sink a target posts its audit events to, and keeps each request's trail.

## Offers
- `auditEvents`: the need a scene states to read them (`need`), and a running target's trail (`of`).
- `auditSink` (→ its URL and its `host:port`, a trail, and its stop), for the package's drivers; a test may give its wait for quiet, to order what arrives between waits rather than time it.

## Invariants
- A request's trail is its result with the events that arrived from its start until none came for a short while.
- A trail starts once none has come for that while, since events go out after the answer.
- Anything but an event posted as one JSON object fails the scene when the target stops.

## Depends on
- The package's `Started` and its fake HTTP server.
