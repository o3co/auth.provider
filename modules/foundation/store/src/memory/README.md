# memory

Internal module of `store`: the store kept in memory, in one process.

## Responsibilities
- Holds the memory implementation of the `store` contract: data in memory (`memoryData`), a store over data of its own (`memoryStore`), and a process over the data, which keeps `upkeep`'s contract as one process (`memoryProcess`).
- Is not safe on many instances: its `honours` answers durable and replicated unmet.
- Offers the same store with ports that check nothing (`memoryCore`), for a store that checks its inputs itself.

## Not here
- What a store promises: the `store` contract and its contract test.
- Booting it, and refusing spaces that need durable or replicated storage without `accept-volatile`: the composition (`./module`).
- A replicated store for tests: the internal module `simulated`.

## Offers
- `memoryData`, `MemoryData`, `memoryStore`, `memoryCore`, `memoryProcess`, `resolveExpiry`: to the package alone.

## Depends on
- `kernel`; `store`'s contract.
