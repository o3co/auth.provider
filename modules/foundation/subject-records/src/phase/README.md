# phase

Internal module of `subject-records`: the phase records are in, as the store's control record keeps it.

## Responsibilities
- Reads the phase from the control record, and tells the mark that turns records indexed.

## Not here
- Writing the mark, and when: the wiring holding the store's upkeep (`account-erasure-store`). What each phase writes: the package's builders.

## Offers
- `subjectRecordsPhase`: `mark` (`subject-records.phase`); `read` (the store's control) → the phase; `readFrom` (a control, or none where the store adapter offers none) → the phase, `reader` for none, a failed read failing; `held` (a control or none) → `HeldPhase`, read once and held for the process, unavailable while the store cannot answer and read again at the next call; `write` (a control record, the store it is of) → the mark to write, or `not-in-maintenance`, then `not-paired`.

## Invariants
- The read is monotone: a mark of `indexed`, in any epoch, reads `indexed`; anything else, or none, `reader`.
- Only `indexed` is ever written, under the maintenance key alone, and only for a store that writes records of two partitions as one: indexed writes need it, so a mark over one without it would refuse every next start; `reader` is the mark's absence, so writers racing all write the same and none turns records back.
- A process reads the phase once, as it starts: records turn indexed for processes started after the mark.

## Depends on
- `store` (the control record), `records` (`changesTogether`)
