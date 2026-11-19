# ledger

Internal module of `store`: the ledger of spaces: which spaces the store's data has ever held, and taking one off.

## Responsibilities
- Declares the ledger's part of `storeUpkeep`, `kept`, `retire` and `sweepKept`, which every implementation offering upkeep keeps alike.

## Not here
- The control record, its epoch and maintenance key, their fences and the refusals of a start: internal module `upkeep`. The ledger's contract cases: upkeep's contract test, which runs them under the key and the fences.

## Offers
- `kept()`: every space ever declared to the store's data, until retired, each with whether a declaration may have held a subject's data (`KeptSpace`).
- `retire(name, generation?)`: takes a space off the ledger, as of the generation a walk read where one is given, until one is required: `retired`, or `declared` (this process declares it), `redeclared` (declared since), `missing`, `not-in-maintenance`.
- `sweepKept(name, cursor?)`, where offered, until every implementation offers it: a page of a kept space's walk (`KeptPage`), or `declared`, `missing`, `not-in-maintenance`. A taker finding it unoffered retires nothing.

## Invariants
- Before its first change, a process adds each space it declares to the ledger; until it has, it changes nothing (each change unavailable) and its readiness says so, retrying. A space's `subjectDataEver` turns true once a declaration names a category other than `none`, and never turns back. Only `retire` takes a space off, under the maintenance key alone, never one the process declares.
- `sweepKept` walks every key of a space on the ledger that this process doesn't declare, under the maintenance key alone, removing and confirming as `sweep` does, each page. It answers counts, the latest expiry and the space's generation, never a key; a sum is exact only at zero.
- `sweepKept`'s cursor is an opaque handle to a walk this process holds, bound to its space; any other is a TypeError. A process holds at most one walk per space: a new walk of a space drops this process's earlier walk of it, and a walk's state goes when it completes or the process ends.
- A space's generation is new on each declaration added. `retire` refuses `redeclared` where it differs from the one given. It catches a declaration, never a writer outside the provider: no other tool runs while a kept space is walked and retired.

## Depends on
- None

## Vocabulary
- ledger: the spaces ever declared to the data.
- generation: a ledger entry's mark, new on each declaration, a string of 1 to 64 characters; compared for equality only.
