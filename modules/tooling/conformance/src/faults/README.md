# faults

Internal module of `conformance`: a Redis topology a fault scene runs on, and the faults of its nodes.

## Responsibilities
- Starts a primary and its replicas in containers on a network of their own, each answering on a port of this host, and removes them.
- Promotes a replica, crashes a node, makes one slow, pauses one, and moves the clock of every node.

## Offers
- `startTopology` (a number of replicas, settings every node starts with, a clock offset), giving the nodes, the current `primary`, its `replicas`, and `stop`; `ask` a node one command.
- A node: its name, `upstream` (where it answers on this host now), `ask`, `runId`, `state` (running, exit code).
- `promote` a replica (only once it has caught up with the primary, within a wait given), killing the old primary or keeping it on, and reattaching the replicas named to the new one; `crash` a node (SIGKILL, then started again, answering how it ended); `sleep` a node (`DEBUG SLEEP`: `awake` with when it began and ended on Redis's clock, from a `TIME` on either side in the same write; `asleep` only a hint, a PING unanswered); `askAll` several commands in one write; `microsOf` a `TIME`; `pause` a node's container.
- `redisImage` and `libfaketime`: the Redis image by version and digest, and the libfaketime package by version.

## Invariants
- Every node fsyncs every write (`appendonly`, `appendfsync always`) and runs Redis as its own user from the start, its debug command allowed, for a slow server.
- A replica that has not caught up is never promoted; its refusal says it is not eligible.
- A request was held by a sleep only where Redis served it at or after the sleep's end; the hint alone proves nothing.
- With the old primary kept on, each primary keeps a replica online.
- A moved clock is libfaketime preloaded with its offset from start, the monotonic clock left alone; the image is the pinned Redis image with the pinned libfaketime, built the same wherever it runs.
- Containers and networks carry the run's process label; those of a process no longer running are removed at the next start, and a start that fails removes what it started.

## Depends on
- Docker; the relay's RESP reader and its upstream.
