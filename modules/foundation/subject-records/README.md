# subject-records

## Responsibilities
- Provides records of spaces that hold a subject's data, written so that erasing a subject finds them and nothing is written past its tombstone; a capability like `records`, built by a feature's wiring, never used by a feature.

## Not here
- What a record holds and how it changes: the feature's. Which feature it serves: the wiring's. How a record is written and kept: `records`, through `changeRecords`. When records are indexed: the phase the wiring reads.

## Offers
- `subjectRecordsIn` (a place, its index space, the phase) → `create` (a key, its subject, a value or its maker, a lifetime: `created`, `exists` or `erased`), `read`, `change`, `remove`, `scan`, by the category the space declares:
  - `online-indexed`: each record's key in its subject's index.
  - `online-keyed`: each record's key made from its subject alone; the index keeps only the subject's tombstone.
- `indexSpaceOf` (a space) → its index space: `.index` after its name, its guarantees, `internal`. The wiring declares it beside the space.
- `Phase`: `reader`, records written raw with no index or tombstone, as they were; `indexed`, the rest below.

## Invariants
- Every write goes through `records`' `changeRecords`, the one door to a space holding a subject's data; a read goes to the store and writes nothing.
- Once indexed, a record is kept in an envelope with its subject (internal module `envelope`), and an owner's value holding `records:v` at its top is refused.
- A subject's part of the index is named by the SHA-256 of the space's name, a line feed and the subject, so no key holds a subject. It holds the tombstone and 16 buckets, each the sorted keys of the subject's records whose SHA-256 starts with that hex digit.
- A create holds the record absent, the subject's tombstone absent and the bucket as read, and writes the record and its key in the bucket, as one.
- `erased` answers a create the tombstone stopped: an owner takes it as refused, never as `exists`, and never tries it again.
- A change holds the record and its subject's tombstone absent, is handed its attempt's deadline, leaves the index as it is, and answers nothing where the tombstone stopped it.
- A removal takes the record and its key from the bucket as one, the bucket going with its last key; no tombstone stops it.
- A record physically held is in its subject's bucket, expired or not: a key leaves a bucket only with its record.
- A record kept raw, from before records were indexed, is changed raw, with no tombstone condition. That is safe: records turn indexed only under the maintenance key, and the one migration indexes or removes every raw record of such a space before erasure can be enabled, so none remains when a tombstone can exist (account erasure §3.3, §5.1).
- Cost: a create or removal rewrites one bucket whole, its size growing with the subject's records (about a sixteenth of them); fine for what an owner keeps per subject, and not capped.
- Refuses at build, through the builder's `refuse`, a store that writes no records of two partitions as one, an index that is not the space's, and a space declaring another category.

## Depends on
- `kernel`, `store`, `records` (`changeRecords`, its targets and keys)

## Vocabulary
- subject: the account a record belongs to. tombstone: a subject's mark that no record of it is written past. bucket: part of a subject's index, the keys of its records.
