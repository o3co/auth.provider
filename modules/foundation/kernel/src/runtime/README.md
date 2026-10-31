# runtime

Internal module of `kernel`: the clock, randomness and log every module is given.

## Responsibilities
- Gives the system clock and randomness, and the log: lines below the level dropped, the rest routed to the sinks.

## Not here
- Which level is set (the kernel section, `config`). Where a line goes once a sink takes it (the sink's module).

## Offers
- `Clock`, `Random`, `Log`, `LogLevel`, `LogFields`, `LogLine`, `LogSink` and `Runtime`; `systemClock` and `systemRandom`.
- `logSinks`, `thresholds` and `Threshold`; `routedLog` (level, clock, the sinks once built) and `guardedLog` (a test's log, made never to throw).

## Invariants
- A log call never throws, so no caller wraps one in try.
- Lines below the level reach no sink; the rest reach every sink in module order, skipping one that throws. Sinks are built first; lines logged meanwhile are dropped.
- A test's runtime keeps its own log.
- A field never takes an envelope name (`level`, `event`, `at`), so a sink may write both as one object; the methods' type refuses one written by name, and a value typed only by an index signature (`LogFields` itself) passes it, its field dropped by the sink.

## Depends on
- None; the package's handles
