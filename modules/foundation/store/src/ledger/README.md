# ledger

Internal module of `store`: the ledger of spaces: which spaces the store's data has ever held, and taking one off.

## Responsibilities
- Declares the ledger's part of `storeUpkeep`, `kept` and `retire`, which every implementation offering upkeep keeps alike.

## Not here
- The control record, its epoch and maintenance key, their fences and the refusals of a start: internal module `upkeep`. The ledger's contract cases: upkeep's contract test, which runs them under the key and the fences.

## Offers
- `kept()`: every space ever declared to the store's data, until retired, each with whether a declaration may have held a subject's data (`KeptSpace`).
- `retire(name)`: takes a space off the ledger: `retired`, or `declared` (this process declares it), `missing`, `not-in-maintenance`.

## Invariants
- Before its first change, a process adds each space it declares to the ledger; until it has, it changes nothing (each change unavailable) and its readiness says so, retrying. A space's `subjectDataEver` turns true once a declaration names a category other than `none`, and never turns back. Only `retire` takes a space off, under the maintenance key alone, never one the process declares.

## Depends on
- None

## Vocabulary
- ledger: the spaces ever declared to the data.
