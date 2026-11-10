# subject-records

## Responsibilities
- Provides records of spaces that hold a subject's data, written so that erasing a subject finds them and nothing is written past its tombstone; a capability like `records`, built by a feature's wiring, never used by a feature.

## Not here
- What a record holds and how it changes: the feature's. Which feature it serves: the wiring's. How a record is written and kept: `records`, through `changeRecords`. When records are indexed: the phase the wiring reads.

## Offers
- `subjectRecordsIn` (a place, its index space, the phase) → `create` (a key, its subject, a value or its maker, a lifetime: `created`, `exists` or `erased`), `read`, `change`, `remove`, `move`, `scan`, by the category the space declares:
  - `online-indexed`: each record's key in its subject's index; `move` gives a record to another subject.
  - `online-keyed`: each record's key its subject itself, one per subject (any other key, TypeError); the index keeps only the subject's tombstone.
  - `bounded`: each record written raw, fenced at creation by its subject's tombstone, gone by its end, at most the space's `boundedMs`.
- `secret` (bounded only) keys records by secrets, as records under a secret are.
- `subjectKeyedSetsIn` (internal module `sets`) → keyed sets of `online-indexed` and `online-keyed` spaces.
- `eraseSubject` (internal module `erase`: a place, a subject) → the space's `SpaceReport`; `sweepIndex` → a page of the index swept of entries whose records or sets are gone.
- `subjectRecordsPhase` (internal module `phase`): its mark, `read` (the store's control, once as a process starts, monotone) and `write` (the mark turning records indexed, only under maintenance; `reader` is its absence, which no write makes).
- `indexSpaceOf` (a space) → its index space: `.index` after its name, its guarantees, `internal`. The wiring declares it beside the space.
- `Phase`: `reader`, records written raw with no index or tombstone, as they were; `indexed`, the rest below, from the mark `subject-records.phase`.

## Invariants
- Every write goes through `records`' `changeRecords`, the one door to a space holding a subject's data; a read goes to the store and writes nothing.
- Once indexed, a record of an `online-*` space is kept in an envelope with its subject (internal module `envelope`), and an owner's value holding `records:v` at its top is refused. Before, every value is raw by the phase, whatever its shape, and the one migration reads every value it meets so.
- A subject's part of the index (internal module `index`) holds its tombstone and 16 buckets, each the sorted entries of the subject's records and sets whose key's SHA-256 starts with that hex digit: a key, and whether it lists the record or the set; no key holds a subject. A bucket in another shape is refused wherever it is read, never skipped.
- A create holds the record absent, the subject's tombstone absent and the bucket as read, and writes the record and its entry in the bucket, as one.
- A value may be made from the attempt's deadline: owners whose value bounds a time by the write, as subject-revocation's boundaries do, need it.
- `erased` answers a create the tombstone stopped: an owner takes it as refused, never as `exists`, and never tries it again.
- A change holds the record and its subject's tombstone absent, is handed its attempt's deadline, leaves the index as it is, and answers nothing where the tombstone stopped it.
- A removal takes the record and its entry from the bucket as one, the bucket going with its last entry, a set under the key keeping its own; no tombstone stops it.
- A move holds both subjects' tombstones absent and rewrites the envelope and both buckets as one: `moved`, `missing`, `not-from` or `erased`.
- A record or set physically held is listed in its subject's bucket, expired or not: an entry leaves a bucket only with what it lists. A set never changes subject.
- A bounded record lives 1 ms to `boundedMs`, never endless (TypeError), and keeps its end on a change; a tombstone fences only its creation. Erasing reports it `fenced` until the tombstone's deadline, `boundedMs` and 5 minutes: the tombstone commits by its deadline on the store clock, so every record created before it ends by then, the 5 minutes allowing for a store clock stepped back, as hosts keep synchronized clocks (security model, what the deployment does).
- With secret keys, a bounded record created before erasure may be used after it until its end: an auth code redeemed so has its tokens refused at token-endpoint's fence.
- A record kept raw, from before records were indexed, is changed raw, with no tombstone condition. That is safe: records turn indexed only under the maintenance key, and the one migration indexes or removes every raw record of such a space before erasure can be enabled, so none remains when a tombstone can exist (account erasure §3.3, §5.1).
- Cost: a create or removal rewrites one bucket whole, its size growing with the subject's records (about a sixteenth of them); fine for what an owner keeps per subject, and not capped.
- Refuses at build, through the builder's `refuse`, a store that writes no records of two partitions as one, an index that is not the space's, a space declaring another category, and secret keys outside `bounded`.
- Erasing writes the tombstone first, then removes only what reads absent or names the subject (internal module `erase`).

## Depends on
- `kernel`, `store`, `records` (`changeRecords`, its targets, keys and keyed sets' codec), `erasure-extensions` (the report)

## Vocabulary
- subject: the account a record belongs to. tombstone: a subject's mark that no record of it is written past. bucket: part of a subject's index, the entries of its records and sets.
