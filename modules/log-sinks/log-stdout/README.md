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

## Data
- None: it holds no state, so it is safe on multiple instances.

## Depends on
- `kernel`; Node's built-ins only.
