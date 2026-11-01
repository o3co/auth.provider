# audit-stdout

## Responsibilities
- Contributes the audit receiver `stdout` to `audit`, writing each event as one line of JSON on standard output.

## Not here
- Which events there are and what they carry: the emitting side's.
- Collecting the lines from standard output: the platform's.
- Counting and logging a failed write: `audit`'s.

## Offers
- Composition definition only: the receiver `stdout`.

## Invariants
- One line per event: one JSON object with its `kind`, `at` (epoch ms), and its `subject` and `attributes` where given, values included.
- A line break inside a value is escaped, so no value can start another line.
- A line carries no `level`, so it is told apart from a log line.
- A write that fails is this receiver failing; the event is not written again.
- Once standard output's reader has gone, each write fails so, counted by `audit`, and never ends the process: the stream's `error` is heard, by one listener however many compositions start.

## Data
- None, so it is safe on many instances.

## Depends on
- `kernel`, `audit`
