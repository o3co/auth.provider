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

## Invariants
- A process starts in this order, so a refused one writes nothing:
  - its declarations are checked;
  - it is refused (kernel's `BuildRefused`) under the maintenance key unless its assembly is never started (`neverStarted`, `true` alone), and without a space the data `requires` unless it is never started and under the key;
  - only then does it take the record's epoch and add its spaces to the ledger.

## Depends on
- `kernel`; `store`'s contract.
