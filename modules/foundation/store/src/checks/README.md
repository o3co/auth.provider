# checks

Internal module of `store`: the checks every implementation's ports go through.

## Responsibilities
- Holds every implementation to the store contract at its boundary (`checkedStore`), and to the upkeep contract at its own (`checkedUpkeep`): each input read once into plain data, each key in a declared space, and a whole batch checked before anything is written.

## Not here
- What the contract promises: `store`'s contract, and `upkeep`'s.
- Answering: each implementation, behind these checks.

## Offers
- `checkedStore(inner, declared)` and `checkedUpkeep(inner, declared)`, on `.`.

## Invariants
- Input is copied once at the boundary and checked: plain JSON only (no accessors, classes, `__proto__` or hidden properties; -0 is 0), well-formed strings, integers in range.
- A batch is checked whole before anything is written, never writes a key twice, and never reaches outside its partition. A batch across is checked the same, and refuses spaces of other guarantees, so a fault keeps or drops it whole.

## Depends on
- `store`'s contract (its types alone; the contract never imports this), `upkeep` (its types), `writer`.
