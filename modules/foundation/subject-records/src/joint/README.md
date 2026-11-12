# joint

Internal module of `subject-records`: records of several `online-indexed` places, changed as one by the ops their owner decides.

## Responsibilities
- Writes the records a change names as one, each op held and written by `writes`' own rule for it, every subject an op names held by its tombstone in that write.

## Not here
- What each op holds and writes, one record at a time: `writes`' rules (`rulesOf`), the one statement of them. The phase: the places', given (or read once: `phased`'s `phasedJointRecordsIn`).

## Offers
- `jointRecordsIn` (places by name, where, the builder's `refuse`) → `changeSubjectRecords` (targets, each a place's name and a key; optionally `watch`, naming more by what they hold; `decide`, an op or none for each target and each watched record) → `written`, each record's before and after, opened (`{ value, subject? }`), or `refused` at one record (`at`: targets or watched, by index) and why (`exists`, `erased`, `missing`).
- Ops: `create` (a value, a lifetime, its subject last), `change` (a value, optionally a lifetime), `remove`, `move` (a value, the subject it goes to).

## Invariants
- Refuses at build, through `refuse`: a place not `online-indexed`; a store writing no records of two partitions as one, in either phase; places on two stores, or of differing guarantees.
- One write: every record named, read and held as read, its op's index records and tombstones among them; a race reads all again and decides again (`decide` is pure). Ops on one bucket compose. A record takes one op.
- Refused: nothing written. A decide giving no op answers `written`.
- `create`: refused `exists` where held, `erased` where its subject's tombstone stands. `change`: `missing` where gone, `erased` where its envelope's subject's tombstone stands, finer than the single `change`'s nothing. `remove`: never refused; a record gone reads before and after alike.
- `move` goes from the subject the record is read under: under another, rebucketed, `erased` where `to`'s tombstone stands, and Unavailable, nothing written, where only the prior subject's does: transient, as that record awaits its eraser. Under `to` already, a `change`. Kept raw (`reader`, or before the migration), moved raw under `change`'s rule, its new value read by the migration.
- The prior holder's erasure shows two ways: a `move` from it is Unavailable; a `change` of its own record answers `refused` (`erased`), the owner reading it by `at`.
- Two subjects in one change are allowed: each one an op names has its tombstone held.

## Depends on
- `kernel` (Unavailable), `records` (`changeRecords`, `changesTogether`), `store`; internal modules `index`, `writes` (`rulesOf`)
