# phase

Internal module of `subject-records`: the phase records are in, as the store's control record keeps it.

## Responsibilities
- Reads the phase from the control record, and tells the mark to write for a phase.

## Not here
- Writing the mark, and when: the wiring holding the store's upkeep (`account-erasure-store`). What each phase writes: the package's builders.

## Offers
- `subjectRecordsPhase`: `mark` (`subject-records.phase`); `read` (the store's control) → the phase; `write` (a control record, a phase) → the mark to write, `not-in-maintenance` or `stays-indexed`.

## Invariants
- The read is monotone: a mark of `indexed`, in any epoch, reads `indexed`; anything else, or none, `reader`.
- A mark is written only under the maintenance key; `reader` once indexed answers `stays-indexed`, never a mark the read would ignore.
- A process reads the phase once, as it starts: records turn indexed for processes started after the mark.

## Depends on
- `store` (the control record)
