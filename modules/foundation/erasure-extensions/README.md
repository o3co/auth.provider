# erasure-extensions

## Responsibilities
- Owns the contract between account erasure and the owners of what it erases: each owner's eraser, the reports of what erasing did, and the names of the marks erasure keeps.

## Not here
- Erasing: each owner's eraser, over `subject-records`, which makes the reports. When and how erasure runs, its journal and its answers: `account-erasure`. Where a store keeps marks: `store`.

## Offers
- The extension point `erasers`, keyed by an eraser's name, which a space's `erasedBy` gives.
- `Eraser`: `online` (one subject, while serving), `window` (subjects, under the maintenance key) and `migrate` (once, under the maintenance key), each taking an `AbortSignal`; `window` and `migrate` take a `Walk` the tool hands in.
- `Erased`: an eraser's `SpaceReport`s and `logoutGaps`, the logout notices it could not tell were delivered, 0 for an eraser with no notices to lose.
- `SpaceReport` (`erased`, `fenced` with its `until`, `stopped` with why) and `MigrationReport` (`migrated` with what was indexed and removed, `stopped`), each naming its space by its declared name.
- `Walk`: a walk of a space by name, removing what expired, each page naming its server.
- `erasureMarks` (`account-erasure.enabled`, `account-erasure.journal`) and `JournalMark`, the journal's header id and last number as the control record keeps them.
- `erasureEnabledFrom` (a control record read for its marks, or none) → `erasureEnabled`, the `enabled` mark's presence in any epoch, read when asked; nothing where no control record is offered, so a store wiring needs no branch of its own.

## Invariants
- A report is made by `subject-records` alone, which erases and so can tell what it wrote; an eraser passes reports on and never writes one. The types carry `ReportMade`, a brand only a visible cast gives.
- An `erased` or `fenced` report means the subject's tombstone is written in that space.
- A run cut short answers `stopped` (`aborted`) for each space it did not finish.
- Spaces are named by their declared names, so nothing here depends on `store`.
- `enabled` holds `true` and counts in any epoch it was written in; only its presence is read, so no value written later weakens it.

## Depends on
- `kernel` (extension points)

## Vocabulary
- eraser: an owner's part that erases a subject's data from the owner's spaces.
- tombstone: a subject's mark in a space that no record of it may be written past.
