# resolver-process

Internal module of `outbound`: name lookups run as the system runs them, in a helper process of their own, ended where no one waits on them.

## Responsibilities
- Starts one helper process per pool, sends it each lookup, and reads its answer.
- Ends a helper whose running lookups no one waits on, or that fails, and starts another; holds each lookup's place until its answer or its helper's confirmed end.

## Not here
- Sharing a lookup among those waiting on it, and each one's deadline: the caller's.
- What a name's addresses may be: `outbound-policy`'s.
- When to stop: the caller's, `outbound`'s stop hook, which `kernel` runs at a stop and when it refuses the composition after the helpers started (its rollback).

## Offers
- `resolverPool` (`pool`, the name it logs; `size`, the lookups at once and the helper's threads; `warn`; `now`, the kernel's clock): `start`, `stop`, and `run(name, family?)`, a `Job` (`answer`, `want`, `unwant`) or none where the helper is not ready or no place is free.
- `ResolutionFailed` (`reason`: `not-found`, `too-many`, `fault`, `refusing`, `stopped`); `poolLimits`.

## Invariants
- The helper is `helper.mjs`, started by `process.ts` in the form guard holds it to: this node, a 16 MiB heap, none of the parent's environment but `LOCALDOMAIN`, `RES_OPTIONS`, `HOSTALIASES` and its thread count, no standard input or output. It resolves with the system's `lookup` (all addresses, in its order) and answers the addresses or the error's code alone. It ends itself once its parent's channel is gone.
- With no one waiting, its recovery never keeps the parent alive: its timers (a wait for ready, a backoff, a window, a look again) let it end as it would. `start` is one start, shared by every call, so a pool never runs two helpers.
- It keeps the parent alive while someone waits on one of its lookups, and through its first start until it is ready or its end is seen, a start refused so never cut short; it lets the parent go otherwise.
- A helper's states: starting, ready, being ended, stopping, ended. Being ended and stopping are not undone: no one may wait on its lookups again (`want` is false), none is taken, and a dropped channel or an error changes nothing. Only its confirmed end (or no process ever started, its error taken however late) gives its places back and decides the next.
- A helper whose running lookups are all left (`unwant` to none, or the last one waited on answered) is killed and started again at once, at most 60 times in 60 seconds; past that it is kept, its places held, and looked at again once the window frees. A helper's end drops its look again; the next one schedules its own.
- An answer of another generation, an unknown lookup, both shapes or neither, a code outside the lookup's, no address, one that is no address, or IPv6 for IPv4 alone is a fault: the helper is killed, its lookups fail at once (`fault`), its places held until its end. So are a dropped channel, an exit of its own, and no ready within 5 seconds. A helper that never ends holds its places and is warned of every 30 seconds.
- More than 64 good addresses fail that lookup alone (`too-many`); nothing is cut before the policy checks them.
- After a fault, it is started again after a backoff from 100 ms, doubling to 5 seconds, and back to 100 ms once one answers; past 30 such starts in 60 seconds, its lookups fail at once (`refusing`) until the window frees.
- The first start's failure is final: `start` rejects and nothing is started again. `stop` may be called any number of times, even while starting or waiting to start again: it ends the helper, holding the parent until its end is seen, and waits for it.
- It logs `outbound.resolver_fault` (pool, reason), `outbound.resolver_recovered`, `outbound.resolver_restarts` (pool, restarts) and `outbound.resolver_stuck` (pool), never a name or an address.

## Depends on
- node's `child_process` (`fork` alone, in `process.ts`) and `dns/promises` (`lookup` alone, in the helper); `net` (`isIP`, to check an answer's addresses) and `path` (`join`, the helper's file).
