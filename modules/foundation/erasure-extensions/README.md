# erasure-extensions

## Responsibilities
- Owns the contract between account erasure and the owners of what it erases: each owner's eraser, the reports of what erasing did, and the names of the marks erasure keeps.

## Not here
- Erasing: each owner's eraser, over `subject-records`, which makes its `SpaceReport`s, or as the owner of a `pseudonymous` space, which makes its `ForgottenReport`. When and how erasure runs, its journal and its answers: `account-erasure`. Where a store keeps marks: `store`.

## Offers
- The extension point `erasers`, keyed by an eraser's name, which a space's `erasedBy` gives.
- `Eraser`: `online` (one subject, while serving), `window` (subjects, under the maintenance key) and `migrate` (once, under the maintenance key), each taking an `AbortSignal`; `window` and `migrate` take a `Walk` the tool hands in. `erasable` (required in 0.20, optional and read as true in 0.22, removed after): whether it can erase every space it erases on the stores behind it; for a space `subject-records` reports, that its store has the erase ports. `after`: the erasers, by name, it follows.
- `SubjectOf` (`subject`, `orphan`, `unreadable` with why) and `SubjectReading`: an owner's reading of a record's subject from its key and stored value, for a migration.
- `SetReading`: the owner's reading of a keyed set's subject from the key alone, the same three answers, an orphan set proven by its key's form, never by what it holds, and a lookup's confirmed "none" `unreadable`, never `orphan`.
- `Elsewhere`: the owner's step for an orphan before its removal, keeping what it holds outside the space, durable and confirmed, idempotent; a throw stops the space.
- `Erased`: an eraser's reports and `logoutGaps`, the logout notices it could not tell were delivered, 0 for an eraser with no notices to lose.
- `SpaceReport` (`erased`, `fenced` with its `until`, `stopped` with why) and `MigrationReport` (`migrated` with what was indexed and what was removed: orphans, those the owner kept elsewhere first among them; `stopped`), each naming its space by its declared name.
- `OwnerStopped` (`owner-stopped`, with why) and `ownerStopped(reason)`, which makes one: an owner's answer, among `migrate`'s, that it cannot migrate yet, read as not finished as `stopped` is; the reason says what is missing or when to run again, and names in the owner's words the part stopped where it has several spaces. It names no space: its reader knows the eraser that answered, and its spaces through `erasedBy`.
- `ForgottenReport` (`forgotten`, with what the run removed) and `forgottenIn(space, removed)`, which makes one: the owner of a `pseudonymous` space claims that nothing it keeps there under the subject's id, as its card bounds it, remains, beyond a record of its own that says only that the subject was erased there.
- `Walk`: a walk of a space by name, removing what expired, each page naming its server.
- `erasureMarks` (`account-erasure.enabled`, `account-erasure.journal`) and `JournalMark`, the journal's header id and last number as the control record keeps them.
- `erasureEnabledFrom` (a control record read for its marks, or none) → `erasureEnabled`, the `enabled` mark's presence in any epoch, read when asked; nothing where no control record is offered, so a store wiring needs no branch of its own.

## Invariants
- A `SpaceReport` or `MigrationReport` is made by `subject-records` alone, which erases and so can tell what it wrote; an eraser passes them on and never makes one. The types carry `ReportMade`, a brand only a visible cast gives. A `ForgottenReport` carries none: it states no tombstone; nor does an `OwnerStopped`, which states nothing written.
- An `erased` or `fenced` report means the subject's tombstone is written in that space.
- A run cut short answers `stopped` (`aborted`) for each space `subject-records` reports; an eraser over no such space throws the signal's reason. An eraser that throws, abort included, is not done, and running it again finishes it.
- An eraser that cannot erase its spaces answers empty reports: `erasable` carries the fact, known at build.
- An eraser's build collects no `probes`, directly or through what it takes: a module that collects `erasers` may be one a probe takes.
- Only `orphan` lets a migration remove a record; `unreadable`, a failed lookup among them, stops the space and removes nothing.
- Spaces are named by their declared names, so nothing here depends on `store`.
- `enabled` holds `true` and counts in any epoch it was written in; only its presence is read, so no value written later weakens it.

## Depends on
- `kernel` (extension points)

## Vocabulary
- eraser: an owner's part that erases a subject's data from the owner's spaces.
- tombstone: a subject's mark in a space that no record of it may be written past.
- forgotten: a `pseudonymous` space's report kind. The owner's record that the subject was erased there is not a tombstone: no `erased` or `fenced` report stands on it, whatever it refuses in the owner's own space.
