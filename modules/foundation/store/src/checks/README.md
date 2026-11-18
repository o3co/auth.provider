# checks

Internal module of `store`: the checks every implementation's ports go through.

## Responsibilities
- Holds every implementation to the store contract at its boundary (`checkedStore`), and to the upkeep contract at its own (`checkedUpkeep`): each input read once into plain data, each key in a declared space, a whole batch checked before anything is written, and the subject writer asked of a change, through the store's ports, to a space of the four categories below.

## Not here
- What the contract promises: `store`'s contract, and `upkeep`'s.
- Answering: each implementation, behind these checks.

## Offers
- `checkedStore(inner, declared)` and `checkedUpkeep(inner, declared)`, on `.`.

## Invariants
- A malformed declaration refuses the boot as kernel's `BuildRefused`: its `where` the space's name, or `store.declaration` where it has none to give: no name, one not a string, one a getter holds, or one kernel's bounds on a `where` refuse; its reason store's fixed text, never what the declaration holds. Input to the ports is refused as a `TypeError`.
- Input is copied once at the boundary and checked: plain JSON only (no accessors, classes, `__proto__` or hidden properties; -0 is 0), well-formed strings, integers in range.
- A batch is checked whole before anything is written, never writes a key twice, and never reaches outside its partition. A batch across is checked the same, and refuses spaces of other guarantees, so a fault keeps or drops it whole.
- A change through the store's ports to a space of `online-indexed`, `online-keyed`, `bounded` or `internal` data carries the subject writer (upkeep's `sweep` and `retire` are no such change and carry none):
  - any single-key change there, and a batch or a batch across touching such a space without it, a key it only reads included, is refused as a `TypeError` before anything is written; the writer is taken on a change to any other space too;
  - it stops a wiring, or a records plain port, of this workspace from writing subjects' data, and stops an accident; it is no boundary against a deployment's own code.

## Depends on
- `kernel` (`BuildRefused`), `store`'s contract (its types alone; the contract never imports this), `upkeep` (its types), `writer`.
