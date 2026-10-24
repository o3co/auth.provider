# records

## Responsibilities
- Provides records that know no feature: keyed records, records under a secret, deferred work, and keyed sets.
- Keeps `store` vocabulary inside: keys within a space, conditional rewrites and their retries, marks and deadlines, shards of deferred work.

## Not here
- What a record holds and how it changes: the feature's. Which feature it serves: the wiring's. Store implementations.

## Offers
- Keyed records: create if absent, read while it lives, change from what it holds, remove, and a scan of the keys of those living, by pages, as `store` walks (a scanned space holds records by key alone); a lifetime is ms from the write, or endless.
- Records changed together: `changeRecords`, records of spaces of the same guarantees on one store, and the records the decision watches from them, any of them written, as one; `changeTogether`, two of them, only the two written; `changesTogether` tells whether a store can. `pairedRecordsIn` pairs a place's records so, and `pairedRecordsAcross` the records of two places, each refusing through the builder's `refuse` where its store cannot.
- Records under a secret: the same but the scan, kept under a name made from the secret, reached by secret or by name. They hold short-lived values only, so a rotation waits them out and they need no scan.
- Deferred work: add, done, and each, which hands the work over; work that fails stays and is counted.
- Keyed sets: add a member for a lifetime (answering those pushed out over the cap), the members with their time left, remove a member; the members pushed out and awaiting, and settling one.
- No contract of its own: the wiring builds each over a place, with the cap and `kernel`'s clock for keyed sets.
- Test stand-ins (`./testing`): records (several of them changed together too), deferred work and keyed sets in memory, a race on demand, and jobs that crowd one shard.

## Invariants
- A change runs again on what is there after a lost race, so it must be pure; after 8 lost races it is unavailable.
- A write whose answer was lost is resent under the same unguessable mark, so it takes effect once, for up to 10 seconds of pauses; a send past its deadline is refused, and any error but unavailable is thrown at once.
- Records changed together are read, the watched ones with them, and held by one write's conditions (the ones kept unchanged too); another writer of any of them first makes it read all again, the watch too, and decide again. A record named twice is read once, held once, and written from one naming at most. Nothing written is confirmed the same way. It is one store's batch across, so a store without one, two stores, or a target named twice is refused.
- Every answer is confirmed: a rewrite that writes nothing (no change, no record, a set gone), a create that finds a record, and a remove that finds none confirm what they read with a write of their own.
- Reads are confirmed only in a space that declares confirmed reads; a feature that decides on them states it among its needs.
- Records and deferred work leave expiry to the store; keyed sets read only `kernel`'s clock; no two clocks are compared.
- Records hold JSON values. A change without a lifetime keeps the record's; a lifetime under 1 ms is 1 ms.
- A keyed set is one record per key, rewritten whole, so its cap stays small; anything in it that is not a member is no member.
- A member ends at its add's time plus its lifetime on `kernel`'s clock, however late the write lands; the set is kept ten minutes past its last end. What an add pushes out awaits in that same write, until its caller settles it or its end passes, so a caller stopped between the add and its own work finds it again. A set kept as a bare list, as before, reads as members alone.
- Over the cap, the other members ending first are pushed out (ties by code point order), never the one being added, and that is logged with the space. A cap is a whole number from 1.
- Deferred work is split over shards of a size the wiring decides; a full shard refuses an add as unavailable and logs it with the space, and nothing kept is pushed out.
- Work stays until done; adding listed work writes again, as the listing may be another request's not yet confirmed.
- A secret's name is `1.` and the base64url SHA-256 of the space's name, a line feed and the secret; the store never receives the secret.
- A space holds records or records under a secret, never both: opening it for the other kind on the same store refuses the boot (`kernel`'s `BuildRefused`: `<space>`, `a space holds records or secret records, not both`), as the records' scan would list the names kept under secrets.
- A name never changes within its version (a new way raises it, and the old is read for the records' lifetime); short codes a person types never go through it.
- Changing the interface shape changes every wired feature's contract, so it goes through a human gate.

## Depends on
- `kernel`, `store`

## Vocabulary
- record: one value per key. deferred work: work named by a string, kept until done. place: the store and space the wiring gives, with `kernel`'s randomness and log.
- secret: an unguessable value (at least 128 random bits) its holder presents to reach its record. name: the key it is kept under, from which the secret cannot be had.
