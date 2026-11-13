# probe

Internal module of `redis`: the readiness probe `redis`.

## Responsibilities
- Answers ready while both connections answer and the server still gives what the package checks.

## Not here
- What is checked of the server, and the connections: the package's.

## Offers
- `redisProbe` (the connections, what no longer holds as the package checks it, the log, the clock): the probe `redis` for `kernel`'s `probes`.
- `goodReplicaProblems` (`INFO replication`'s text, the server's `min-replicas-to-write`): fewer good replicas (`min_slaves_good_slaves`) than it needs, as a problem; nothing where either is not shown.

## Invariants
- Each run PINGs both connections; a dropped one fails at once, as the client keeps no offline queue.
- At most once a second (a fixed pace, shorter than any probe period), counted from its start, it checks again what the package checks; a run within that second reads its answer, pass or fail, and joins it while it runs. A clock set back runs anew.
- Anything that no longer holds answers unready, logging `redis.settings_unmet` with it when that changes, not on every run.
- With `replicas`, the package asks too whether replicas are good enough for the server to take writes, short of which it answers unready; boot never asks it, so a passing want of replicas leaves boot alone.
- With `replication`, a primary demoted after boot answers the confirming `SET` `READONLY`: the run fails (`kernel.probe_failed`), with no `redis.settings_unmet`.

## Depends on
- `kernel` (probes, the clock and the log); `ioredis`
