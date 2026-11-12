# subject-records

## Responsibilities
- Provides records of spaces that hold a subject's data, written so that erasing a subject finds them and nothing is written past its tombstone; a capability like `records`, built by a feature's wiring, never used by a feature.

## Not here
- What a record holds and how it changes: the feature's. Which feature it serves: the wiring's. How a record is written and kept: `records`, through `changeRecords`. When records are indexed: the maintenance tool, writing the phase's mark.

## Offers
- `subjectRecordsIn` (internal module `writes`): a subject's records in a space declaring `online-indexed`, `online-keyed` or `bounded`.
- `subjectKeyedSetsIn` (internal module `sets`): keyed sets of `online-indexed` and `online-keyed` spaces.
- `phasedRecordsIn`, `phasedKeyedSetsIn` (internal module `phased`): the builders over the phase read once, with the space's `erase` and `migrate` and `ready` for the template's probe.
- `eraseSubject` (internal module `erase`) → the space's `SpaceReport`; `sweepIndex` → a page of the index swept of entries whose records or sets are gone.
- `migrateRecords` (internal module `migrate`) → the space's `MigrationReport`.
- `subjectRecordsPhase` (internal module `phase`): its mark, `read`, `once` → `PhaseOnce`, and `write` (`not-in-maintenance`, then `not-paired`).
- `indexSpaceOf` (a space) → its index space: `.index` after its name, its guarantees, `internal`; the wiring declares it beside the space. `tombstoneFloor` (no eviction, durable, replicated): what a space holding a subject's data declares beside its own needs, as its index keeps the tombstone with the space's guarantees. `SubjectPlace`, `Phase`.

## Invariants
- Every write goes through `records`' `changeRecords`, the one door to a space holding a subject's data; a read goes to the store and writes nothing. In `reader`, each write is one record in one partition, which any store writes as one.
- `reader`: records written raw, with no index or tombstone, as they were. `indexed`, from the mark `subject-records.phase`: a record of an `online-*` space is kept in an envelope with its subject (internal module `envelope`). An owner's value holding `records:v` at its top is refused in both phases.
- A subject's part of the index (internal module `index`) holds its tombstone, 16 buckets of the entries of its records and sets, and, in an `online-keyed` space, the witness of its envelopes; no key holds a subject. A bucket in another shape is refused wherever it is read, never skipped.
- Every write of an `online-keyed` envelope writes its subject's witness with it where missing; erasing removes it with what it witnesses; a removal or an end may leave it, holding nothing but its hashed key.
- `erased` answers a create the tombstone stopped: an owner takes it as refused, never as `exists`, and never tries it again.
- A record or set physically held is listed in its subject's bucket, expired or not, once indexed: an entry leaves a bucket only with what it lists. A set never changes subject.
- A raw record, from before records were indexed, is changed raw, with no tombstone condition. The one migration indexes or removes every raw record of an `online-*` space, or stops that space, before erasure can be enabled. It migrates records only: a keyed set kept raw stays raw and unlisted (account erasure §3.3, §5.1).
- Erasing writes the tombstone first, then removes only what reads absent or names the subject. A report is made by this package alone (internal modules `erase` and `migrate`).
- Cost: a create or removal rewrites one bucket whole, its size growing with the subject's records (about a sixteenth of them); fine for what an owner keeps per subject, and not capped.

## Deprecated
- The builders' `unowned`: raw records of a space from before its non-subject records moved out, saved while the phase is `reader`, `closed` once `indexed`; removed in 0.22 (internal module `writes`).

## Depends on
- `kernel`, `store`, `records` (`changeRecords`, its targets, keys and keyed sets' codec), `erasure-extensions` (the reports, `SubjectReading`, `Elsewhere`, `Walk`)

## Vocabulary
- subject: the account a record belongs to.
- tombstone: a subject's mark that no record of it is written past.
- floor: `tombstoneFloor`, the guarantees a tombstone needs, which every space holding a subject's data declares.
- bucket: part of a subject's index, the entries of its records and sets.
- witness: the index's mark that this package wrote an envelope at a subject's key, telling it from a raw value of its shape.
