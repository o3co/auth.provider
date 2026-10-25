# commands

Internal module of `interop-oidf`: a command a plan runs, held to its time.

## Offers
- `Command`, and `systemCommand`: the system's command, killed (`SIGKILL`) past its own time, or where the plan's deadline (`signal`) aborts.

## Invariants
- Every command has a time of its own; a setup step has the plan's deadline besides, a stop's step runs past it by its own time alone.
