# lookups

Internal module of `outbound`: name lookups shared among those asking a name at once, each waiting until its own deadline, and how many run at once.

## Responsibilities
- Answers everyone asking a name at once with one lookup, in one pool, each waiting no longer than its own deadline and the lookup told when one stops.
- Runs lookups in this process, with the system's resolver, as a pool of its own.
- Says how many lookups run at once, and each pool's share.

## Not here
- Running lookups in a helper process, and ending it: `resolver-process`.
- What a name's addresses may be, and connecting: `outbound`'s.

## Offers
- `lookupsOver(pool)`: `resolve(name, family, signal)`, the addresses, or `LookupRefused` (`unavailable`, `timeout`, `unreachable`).
- `inProcessPool(size, resolve)`: a pool in this process.
- `lookupShares` (`maxLookups`, and `inProcess` with the threadpool's size where lookups run here): the total at once, the deployment's own share and the outside party's; `threadpoolHalf`.

## Invariants
- One map per pool: a lookup is shared only by those asking the same name, for the same family (IPv4 alone shares nothing with every family), in the same pool. The name is as given: `short` and `short.` share nothing.
- Each asker waits on the lookup with `want`, the first one by running it, and stops with `unwant` at its deadline, as `timeout`; the others are still answered.
- A lookup's answer is heard once, for those still waiting on it: an asker gone at its deadline holds nothing of it, however long the lookup runs and however often others join and leave.
- A lookup no one waits on any more is joined by the next asker while the pool lets it be waited on (`want` true); where it does not, the next asker begins another.
- A lookup is taken off the map only where the map still holds it: one ending late never takes off the key's later lookup.
- With no place free, a new lookup is `unavailable` at once; a deadline already past is `timeout` at once; a lookup's own failure is `unreachable`.
- In this process, a lookup holds its place until the system answers, whoever waits; left by all, it is still joined until it ends.
- The outside party's share is half the total, rounded down, the deployment's own the rest. In this process, the total is first held to half the threadpool (`UV_THREADPOOL_SIZE`, four unless set), rounded up and at least one, so both pools full never take more of it.

## Depends on
- `resolver-process` (the `Job` a pool gives).
