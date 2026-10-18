# audit

## Responsibilities
- Takes audit events from the modules that emit them, stamps them with `kernel`'s clock, and hands them to the receivers the operator names.
- Provides the built-in receiver `log`, which writes one log line per event.

## Not here
- The kinds of events and what they hold: the emitting side's.
- Keeping, batching or retrying events: each receiver's.

## Offers
- `audit`: record an event (kind, subject, attributes as names and string values), returning at once.
- `audit`: the losses since boot, per named receiver, for a health check to read; the same as the metric `auth_audit_events_lost_total`, by `receiver`.
- Extension point: receivers, keyed by name, each taking an event.
- `auditEvents`: a module's declaration of its events (each kind's attributes, and when it is recorded), which it exports as `./audit-events` for the audit event reference; `declaredAudit` records only the kinds declared, with their attributes, and throws on another.
- The built-in receiver `log`: the kind, time, subject and the attributes' names, never their values.
- Operator section: `receivers`, their names or `none` (no default); `max-pending` (default 1000), each receiver's deliveries under way at once.
- Test configuration builders, and a stand-in that keeps every event (`./testing`).

## Invariants
- A receiver gets the event frozen, with its time (`at`, epoch ms) from `kernel`'s clock, whatever the emitter wrote.
- The emitter's own attributes are copied, never frozen. A `userAgent`, the request's own text, reaches receivers bounded as 0.17 bounded it: a `?` for each character outside RFC 6749's NQSCHAR, at most 200 characters (a longer one keeps 197 and `...`); the subject and other attributes stay as written.
- Delivery is best effort (tier 1): receivers run after `record` returns, so an answer never waits for its events. One that throws or rejects never changes the emitter's answer or stops the others.
- An event is lost past a receiver's pending limit (never queued), when its receiver fails, or when still under way at the stop deadline: at stop, deliveries under way are awaited until `kernel.stop-deadline`.
- The built-in receiver `log` writes at `info`, so `kernel` drops its lines when the operator's log level is higher; the other receivers are not subject to that level.
- Every loss is counted, and a warning names the receiver once when it starts losing, with the failure's kind alone (`backlog`, `stopped`, or the error's name, never its message), and once when it next takes an event.
- Boot is refused without the section, for a name that is no receiver, for a composed receiver left unnamed or named `log`, and for `none` while a receiver is composed.

## Data
- Each instance's own delivery counts; nothing is shared, so it is safe on many instances.

## Depends on
- `kernel`, `metrics`

## Vocabulary
- audit event: an occurrence the emitting module names and wants on record.
- receiver: a place audit events go.
- lost: an event a receiver did not take.
