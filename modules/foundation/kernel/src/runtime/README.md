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
- A log call never throws. Lines reach every sink in module order, skipping one that throws; lines logged before the sinks are built are dropped.

## Depends on
- None; the package's handles
