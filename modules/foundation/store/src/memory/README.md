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
- A process starts in this order, so a refused one writes nothing: its declarations are checked; then it reads the record once, judging `upkeep`'s refusals of a start on that read (`mayBuildUnderKey`, granted by the composition from kernel's `neverStarted`, `true` alone) and taking its epoch from it; only then does it add its spaces to the ledger.
- memory has no server expiry: only its changes and `sweep` remove what expired; a read removes nothing.
- The data keeps a registry of the processes open on it: a process joins once it has started, never one refused. `detach` first stops the process, each change and read it makes from then on unavailable, and only then takes it off the registry. A process's `alone()` answers from the registry, `accompanied` with the others' count; never `unchecked`, and unavailable only once detached.
- A kept space's walk is held by the process under a handle of the data's name and a count the data never repeats, which alone its cursor names, over the space's keys taken at its first page.

## Depends on
- `kernel`; `store`'s contract; the internal module `checks` (`checkedStore`, `checkedUpkeep`, `declaredSpaces`).
