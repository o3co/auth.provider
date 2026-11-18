# simulated

Internal module of `store`: a simulated replicated store, for tests, offered through `./testing`.

## Responsibilities
- Provides the store over the spaces the composition declares, as a primary and a replica in memory, losing what a space's missing guarantees allow: unconfirmed writes on failover, writes not durable on restart, and entries not kept from eviction under memory pressure.
- Offers a control record of its own whose marks a test writes, and each space as the composition declared it (`declaredSpace`).

## Not here
- What a store promises: the `store` contract and its contract test.
- A store kept in memory for a deployment: the memory store.

## Offers
- `simulatedStore()` → `SimulatedStore`: its module, the faults a test asks for, its marks, and the declared spaces.

## Depends on
- `store`'s contract and its memory store.
