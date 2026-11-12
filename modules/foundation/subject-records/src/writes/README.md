# writes

Internal module of `subject-records`: a subject's records, by the category its space declares.

## Responsibilities
- Creates, reads, changes, removes and scans a subject's records so erasing the subject finds them, and none is created past its tombstone.

## Not here
- Keyed sets: internal module `sets`. Erasing and migrating: internal modules `erase` and `migrate`. The phase: the place's, given (or read once: internal module `phased`).

## Offers
- `subjectRecordsIn` (a place, its index space, the phase; where; the builder's `refuse`; `secret` for a bounded space) → `create` (a key, a value or its maker, a lifetime, its subject last: `created`, `exists` or `erased`), `read`, `change`, `changeNamed`, `remove` (a key, and optionally a check of its value: `removed`, `left` where the check said no, or `missing`), `scan`; and `unowned` (deprecated, below).
- `rulesOf` (a place, its category) → each write's rule: the index records it reads besides the record, named from the record as read, and what it answers and writes from all it read. The one statement of the writes' conditions; `subjectRecordsIn` runs each op through it, one record at a time, and `joint` many as one.
- `online-indexed`: each record's key in its subject's bucket. `online-keyed`: each record's key its subject itself, one per subject (any other key, TypeError). `bounded`: each written raw, fenced at creation by its subject's tombstone, gone by its end, at most the space's `boundedMs`.

## Invariants
- `changeNamed` reaches the same record as `change` by the name it is kept by (records' `secretName`) under a secret, elsewhere by its key: the same rule, its fixed end and its fence alike, so a bounded record is changed by name through its subject's tombstone, which fences only creation.
- `moveTo`, `joint`'s alone, holds a move's three cases: from another subject, rebucketed (`erased` for `to`'s tombstone, `from-erased` for `from`'s alone); to its own subject, or raw, a `change`.
- A create holds the record absent, the subject's tombstone absent and, as read, the bucket (`online-indexed`) or the witness (`online-keyed`), and writes the record with its entry or its witness, as one.
- A value may be made from the attempt's deadline: owners whose value bounds a time by the write, as subject-revocation's boundaries do, need it.
- A change holds the record and its subject's tombstone absent, is handed its attempt's deadline, leaves the bucket as it is, and writes the witness of an `online-keyed` envelope where missing. The builder's `change` of a record whose subject is erased answers as absent, the record held until its eraser removes it (its rule answers `missing` and `erased` apart); a create there answers `erased`.
- A removal takes the record and its entry from the bucket as one, the bucket going with its last entry, a set under the key keeping its own; no tombstone stops it, and an `online-keyed` removal leaves the witness. A removal with a check runs it on the value it holds, raw or opened from its envelope, in the same change: the record removed is the one checked, whatever another request wrote between.
- A bounded record lives 1 ms to `boundedMs`, never endless (TypeError), and keeps its end on a change; a tombstone fences only its creation, so one created before erasure may be changed and used until its end: an auth code redeemed so has its tokens refused at token-endpoint's fence.
- `unowned` (a key, a value, a lifetime) saves a record holding no subject's data raw, unless the key holds one (`exists`), and answers `closed`, writing nothing, once the builder's phase is `indexed`: a plain answer, never a throw. Such records read as orphans to the one migration, through the owner's `Elsewhere`. It has no read, removal or scan of its own.
- `unowned`'s phase is the one the builder was built with (`phased`'s `once`), not a read of the mark at the write; a writer with a stale phase is stopped by the maintenance window's fence, epoch and restarts (account erasure §5.1).
- Refuses at build, through `refuse`: once indexed, a store that writes no records of two partitions as one; an index that is not the space's; another category; secret keys outside `bounded`.

## Depends on
- `records` (`changeRecords`, its targets, `Next`), `store`; internal modules `envelope`, `index`
