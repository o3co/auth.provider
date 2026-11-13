# records

## Responsibilities
- Provides records that know no feature: keyed records, records under a secret, deferred work, and keyed sets.
- Keeps `store` vocabulary inside: keys within a space, conditional rewrites and their retries, marks and deadlines, shards of deferred work.

## Not here
- What a record holds and how it changes: the feature's. Which feature it serves: the wiring's. Store implementations.

## Offers
- Keyed records: create if absent, read while it lives, change from what it holds, remove, a scan of the keys of those living, by pages, as `store` walks (a scanned space holds records by key alone), and a walk handing each value to a visitor (internal module `walk`); a lifetime is ms from the write, or endless. A change is handed, and a create's value may be made from, the deadline its attempt is written with, a retry its own; `writeDeadline` (a store-clock time) is that deadline.
- Records changed together: `changeRecords`, records of spaces of the same guarantees on one store, each by key, by the secret it is kept under or as a keyed set (a space named plainly or by secret in a call), and the records the decision watches from them, any of them written, as one, handing the decision its attempt's deadline; `changeRecords.keyOf`, a target's store key; `changeTogether`, two of them, only the two written; `changesTogether`: whether a store can across partitions.
- `pairedRecordsIn` pairs a place's records so, and `pairedRecordsAcross` the records of two places, each refusing through the builder's `refuse` where its store cannot; `pairedRecordsAcross` also where its places are on two stores or their spaces declare other guarantees. (Both this and the item above: internal module `together`.)
- Records under a secret: the same but the scan (which their `named` records, reached by name, keep), kept under a name made from the secret, reached by secret or by name. They hold short-lived values only, so a rotation waits them out and they need no scan.
- Deferred work: add, done, and each, which hands the work over; work that fails stays and is counted.
- Keyed sets: add a member for a lifetime (answering those pushed out over the cap), the members with their time left, remove a member; the members pushed out and awaiting, and settling one. `keyedSetsIn.codec` (a cap and a clock) is the set's format at rest, its only definition: `keyedSetsIn` writes with it, and subject-records composes it inside `changeRecords`; `keyedSetsIn.strict` reads a stored set strictly, for subject-records' migration. (Internal module `keyed-sets`.)
- No contract of its own: the wiring builds each over a place, with the cap and `kernel`'s clock for keyed sets.
- Test stand-ins (`./testing`): records (several of them changed together too), deferred work and keyed sets in memory, a race on demand, and jobs that crowd one shard.

## Deprecated
- `overCap` and `checkedCap`: exported, unused outside records; the set's format is `keyedSetsIn.codec`. A later release (0.22) removes them.

## Invariants
- A write is retried after a lost race (8 times, then unavailable) and resent under its mark after a lost answer (10 seconds of pauses), as internal module `writing` states.
- Records changed together are read and held by one write, its routing chosen per attempt, as internal module `together` states.
- Every answer is confirmed: a rewrite that writes nothing (no change, no record, a set gone), a create that finds a record, and a remove that finds none confirm what they read with a write of their own.
- Reads are confirmed only in a space that declares confirmed reads; a feature that decides on them states it among its needs.
- Records and deferred work leave expiry to the store; keyed sets read only `kernel`'s clock; no two clocks are compared.
- Records hold JSON values. A change without a lifetime keeps the record's; a change's lifetime under 1 ms is 1 ms.
- A conditional removal is a change: where the record holds what the caller expects, it changes it to a 1 ms lifetime, and from a millisecond later it is read no more.
- Deferred work is split over shards of a size the wiring decides; a full shard refuses an add as unavailable and logs it with the space, and nothing kept is pushed out.
- Work stays until done; adding listed work writes again, as the listing may be another request's not yet confirmed.
- A space holds records or records under a secret, never both: opening it for the other kind on the same store refuses the boot (`kernel`'s `BuildRefused`: `<space>`, `a space holds records or secret records, not both`), as the records' scan would list the names kept under secrets. A space declared to hold a subject's data (`online-indexed`, `online-keyed`, `bounded`) opens through no builder but `changeRecords`, refusing the boot the same way: subject-records writes it.
- A name never changes within its version (a new way raises it, and the old is read for the records' lifetime); short codes a person types never go through it.
- Changing the interface shape changes every wired feature's contract, so it goes through a human gate.

## Depends on
- `kernel`, `store`

## Vocabulary
- record: one value per key.
- deferred work: work named by a string, kept until done.
- place: the store and space the wiring gives, with `kernel`'s randomness and log.
- secret: an unguessable value (at least 128 random bits) its holder presents to reach its record. name: the key it is kept under, from which the secret cannot be had.
