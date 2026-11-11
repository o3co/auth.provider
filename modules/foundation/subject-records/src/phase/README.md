# phase

Internal module of `subject-records`: the phase records are in, as the store's control record keeps it.

## Responsibilities
- Reads the phase from the control record, and tells the mark that turns records indexed.

## Not here
- Writing the mark, and when: the wiring holding the store's upkeep (`account-erasure-store`). What each phase writes: the package's builders.

## Offers
- `subjectRecordsPhase`: `mark` (`subject-records.phase`); `read` (the store's control) → the phase; `once` (a control, or none where the store adapter offers none) → `PhaseOnce`, the phase as one process reads it once and keeps it: unavailable while the store cannot answer, read again at the next call, `reader` with no control; `write` (a control record, the store it is of) → the mark to write, or `not-in-maintenance`, then `not-paired`.
- `held` and `HeldPhase`: `once`'s former names, until consent-store reads `once`.

## Invariants
- The read is monotone: a mark of `indexed`, in any epoch, reads `indexed`; anything else, or none, `reader`.
- Only `indexed` is ever written, under the maintenance key alone, and only for a store that writes records of two partitions as one: indexed writes need it, so a mark over one without it would refuse every next start; `reader` is the mark's absence, so writers racing all write the same and none turns records back.
- A process keeps the first reading that answers: one whose store answered at start holds the phase it read then; one whose store did not reads it at its first call, possibly after the mark, so it may turn indexed after it started. Every node restarts after the mark (account erasure §5.1), so none serves both phases of one space.

## Depends on
- `store` (the control record), `records` (`changesTogether`)
