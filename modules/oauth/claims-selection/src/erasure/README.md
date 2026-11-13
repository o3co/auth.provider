# erasure

Internal module of `claims-selection`: erasing a subject's selections, and reading whose a record written before indexing is.

## Responsibilities
- The eraser `claims-selection`, contributed to `erasure-extensions`' `erasers`, as the selections' space's `erasedBy` names it.

## Not here
- What the store keeps and how it fences (the Store). When erasure runs (`account-erasure`). Whose a family is (the module keeping families, through `familySubjects`).

## Offers
- `selectionEraser` (the store, the family reading if composed) → the eraser: a subject's selections erased through the store's `erase`, a window doing the same for each subject, and `migrate` with `selectionSubjectOf`; `erasable` only where the store offers both ports, empty reports where not. It runs after no other eraser.
- `selectionSubjectOf` (the family reading if composed) → the migration's reading: format 2's own subject; a family's target 0.19 kept without one by its family, ended taken for an orphan; a code's selection, a pin or a token's target 0.19 kept without one unreadable, its reason giving the one bound (86,520 s after the last 0.19 instance stopped, frozen from v0.19.1) and that a stop past it means a 0.19 instance still writes.
- `portsRefused` (the store) → why its ports cannot be used, or none: `erase` and `migrate` together or neither, a part refused at build; `portsOf` → both, or none.

## Invariants
- A record of no kind claims-selection names, or of another shape, is unreadable, never an orphan; so is a family target with no family reading composed, or one whose reading failed.
- Each port is called on the store, so an implementation keeps its own `this`.
- The eraser's build takes only the store and the family reading, collecting no probes: the erasure gate collects erasers.

## Depends on
- `erasure-extensions` (`Eraser`, `SubjectReading`); the package's store interface, record formats and `familySubjects`.
