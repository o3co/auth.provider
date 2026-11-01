# log-stdout

## Responsibilities
- Contributes a sink to `kernel`'s `logSinks`: writes each log line it gets as one line of JSON on standard output.

## Not here
- Which lines there are, their levels, and the operator's level: `kernel`.
- Collecting the lines from standard output: the platform's.
- The audit stream: `audit-stdout`.

## Offers
- Composition definition only: the sink.

## Invariants
- One output line per log line: a JSON object with `level`, `at` (epoch ms) and `event` first, then the fields.
- A field named `level`, `at` or `event` is dropped; the line's own values stand.
- Line breaks and control characters in values are escaped by JSON, so one log line never spans two output lines.
- A line always carries `level`, which tells it apart from an audit line.
- Once standard output's reader has gone, a line it cannot write is dropped and never ends the process: the stream's `error` is heard, by one listener however many compositions start.
- At stop, the lines it has queued are written out before the stop ends, within `kernel.stop-deadline`, its hook running after the modules that log stopped; past the deadline its hook is called with the aborted signal and does not wait, so the lines then queued, `kernel.stop_failed` among them, are lost, and not counted.

## Data
- None: it holds no state, so it is safe on multiple instances.

## Depends on
- `kernel`; Node's built-ins only.
