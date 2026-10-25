# lifecycle

Internal module of `kernel`: what runs once the assembly starts, and how it stops and answers readiness.

## Responsibilities
- Runs a periodic task at its interval, never two runs at once; answers readiness from the probes; stops the periodic tasks, then the stop hooks, within a deadline.

## Not here
- Building the modules and handing each its build context (the package's assembly). The log a failure is warned on (`runtime`).

## Offers
- `periodic` (interval, task, log, where) → `start` and `stop`.
- `probes`, `Probe`, `Readiness` and `ReadinessReport`; `readinessOf` (probes, runtime, whether stop has begun) → the report for a deadline; `isTimerMs`.
- `stopWithin` (deadline, the periodic tasks, the stop hooks, log, `during`?) and `StopHook`; `during: "refusal"` for a refused assembly's rollback.

## Invariants
- A periodic task's first run comes one interval after start; its timer, and readiness's deadline timer, leave the process free to end.
- A run still going takes the next tick too; a failed run is one warn line with the error's type, and the next follows.
- A check still running is joined, and aborted once no caller waits; once stop begins, every probe answers down, in a report asked before it too.
- Stop waits for the periodic tasks, then calls the hooks in reverse order, each with a signal that aborts at the deadline; a hook that fails or runs past it is one warn line; the hooks left are called without waiting, their signal aborted, with no `late` line of their own, though a failure of theirs is still warned.
- A hook past the deadline is warned `late`, and again `failed` should it reject later, which may come after a refused assembly's refusal is told.
- A warn line names the thrown value's type, `unknown` where reading it throws (a revoked proxy, a `name` getter that throws), so a malformed throw never stops the hooks left.
- A stop leaves its process free to end; a rollback (`during: "refusal"`) keeps it alive until its hooks end or the deadline passes, so the refusal reaches its host, and marks its warn lines `during`.
- Rollback: an assembly refused after its builds takes its refusals, then runs the stop hooks registered before its factories settled, in reverse, within `stop-deadline` (for asynchronous waits; blocking code runs on), and throws the refusals it took; a failed or late hook is a warn line, never a refusal. Dependents stop first only where each registered after its dependencies resolved; late references order nothing. One refused before any build runs none.
- A failed periodic run, probe or stop hook is one warn line naming it, with the error's type, never its text. A stop hook past the deadline is one too.

## Depends on
- `runtime` (the log and the runtime's types); the package's handles and freezing; `refusal` (`thrownKind`)
