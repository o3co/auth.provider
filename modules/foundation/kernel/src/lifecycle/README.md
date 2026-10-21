# lifecycle

Internal module of `kernel`: what runs once the assembly starts, and how it stops and answers readiness.

## Responsibilities
- Runs a periodic task at its interval, never two runs at once; answers readiness from the probes; stops the periodic tasks, then the stop hooks, within a deadline.

## Not here
- Building the modules and handing each its build context (the package's assembly). The log a failure is warned on (`runtime`).

## Offers
- `periodic` (interval, task, log, where) → `start` and `stop`.
- `probes`, `Probe`, `Readiness` and `ReadinessReport`; `readinessOf` (probes, runtime, whether stop has begun) → the report for a deadline; `isTimerMs`.
- `stopWithin` (deadline, the periodic tasks, the stop hooks, log) and `StopHook`.

## Invariants
- A run still going takes the next tick too; a failed run is one warn line with the error's type, and the next follows.
- A check still running is joined, and aborted once no caller waits; once stop begins, every probe answers down.
- Stop waits for the periodic tasks, then calls the hooks in reverse order, each with a signal that aborts at the deadline; a hook that fails or runs past it is one warn line, and the hooks left are called without waiting.

## Depends on
- `runtime` (the log and the runtime's types); the package's handles and freezing
