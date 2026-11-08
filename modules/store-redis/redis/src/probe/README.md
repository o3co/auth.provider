# probe

Internal module of `redis`: the readiness probe `redis`.

## Responsibilities
- Answers ready while both connections answer and the server still gives what the package checks.

## Not here
- What is checked of the server, and the connections: the package's.

## Offers
- `redisProbe` (the connections, what no longer holds as the package checks it, the log, the clock): the probe `redis` for `kernel`'s `probes`.

## Invariants
- Each run PINGs both connections; a dropped one fails at once, as the client keeps no offline queue.
- At most once a second, counted from its start, it checks again what the package checks; a run within that second reads its answer, pass or fail, and joins it while it runs. A clock set back runs anew.
- Anything that no longer holds answers unready, logging `redis.settings_unmet` with it when that changes, not on every run.

## Depends on
- `kernel` (probes, the clock and the log); `ioredis`
