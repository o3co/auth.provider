# phase

Internal module of `subject-records`: the phase records are in, as the store's control record keeps it.

## Responsibilities
- Reads the phase from the control record, and tells the mark that turns records indexed.

## Not here
- Writing the mark, and when: the wiring holding the store's upkeep (`account-erasure-store`). What each phase writes: the package's builders.

## Offers
- `subjectRecordsPhase`: `mark` (`subject-records.phase`); `read` (the store's control) → the phase; `write` (a control record) → the mark to write, or `not-in-maintenance`.

## Invariants
- The read is monotone: a mark of `indexed`, in any epoch, reads `indexed`; anything else, or none, `reader`.
- Only `indexed` is ever written, under the maintenance key alone; `reader` is the mark's absence, so writers racing all write the same and none turns records back.
- A process reads the phase once, as it starts: records turn indexed for processes started after the mark.

## Depends on
- `store` (the control record)
