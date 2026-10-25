# faults

Internal module of `conformance`: a Redis topology a fault scene runs on, and the faults of its nodes.

## Responsibilities
- Starts a primary and its replicas in containers on a network of their own, each answering on a port of this host, and removes them.
- Promotes a replica, crashes a node, makes one slow, pauses one, and moves the clock of every node.

## Offers
- `startTopology` (a number of replicas, settings every node starts with, a clock offset), giving the nodes, the current `primary`, the nodes following it (`replicas`), and `stop`.
- A node: its name, `upstream` (where it answers on this host now), `ask`, `runId`, `state` (running, exit code).
- `promote` a replica (only once it has caught up with the primary, within a wait given), killing the old primary or keeping it on, and reattaching the replicas named to the new one; a step a scene takes while writes are held (`between`); the barrier's span.
- `crash` a node (SIGKILL, then started again, answering how it ended), and `pause` a node's container.
- `sleep` a node (`DEBUG SLEEP`): `awake` with when it began and ended on Redis's clock, from a `TIME` on either side in the same write; `asleep` only a hint, a PING unanswered.
- `redisImage`: the Redis image by version and digest.

## Invariants
- Every node fsyncs every write (`appendonly`, `appendfsync always`) and runs Redis as its own user from the start, its debug command allowed, for a slow server.
- A replica that has not caught up, or follows another replication history than the primary, is never promoted; its refusal says it is not eligible.
- Writes to the primary are held from the barrier at which the target is taken until the old primary is killed or, kept on, released.
- Keeping the old primary on needs a replica reattached to the new one and one of its own to stay with it; a choice that leaves either without is refused before anything changes.
- A promotion that fails after the barrier leaves an old primary it did not kill taking writes again.
- A node follows its primary by command, never by a start argument, so one crashed starts again in its current role, following its current primary, checked before `crash` answers.
- A request was held by a sleep only where Redis served it at or after the sleep's end; the hint alone proves nothing.
- With the old primary kept on, each primary keeps a replica online.
- A moved clock is `clock`'s, on the pinned Redis image.
- Containers and networks carry the run's process label; those of a process no longer running are removed at the next start, and a start that fails removes what it started. A container goes with its volume; a crash keeps both.

## Depends on
- Docker; `ask`; `clock`; the relay's answer and upstream.
