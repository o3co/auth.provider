# migrate

Internal module of `subject-records`: the one migration of a space's records or keyed sets written before they were indexed.

## Responsibilities
- Puts each raw record of a space, and each raw keyed set of an `online-indexed` one, into its subject's index, or removes it where its owner proves it has none, once indexed.

## Not here
- Whose a record or set is: the owner's `SubjectReading` or `SetReading`. Walking the space and when the migration runs: account erasure's tool, which hands in the `Walk`. Whether a set is well formed: `records`' `keyedSetsIn.strict`.

## Offers
- `migrateRecords` (a place, a `Walk`, the owner's `SubjectReading`, a signal, and optionally the owner's `Elsewhere`) → a `MigrationReport`: `migrated` with what was indexed and what was removed: orphans, those the owner kept elsewhere first among them; or `stopped` with why (`not-indexed`, `aborted`, `unavailable`, `index-unreadable`, `walk-unsteady`, `unreadable: …`, `elsewhere: …`, `a record keyed by another subject`).
- `migrateSets` (a place, a `Walk`, the owner's `SetReading`, a signal) → a `MigrationReport`, the same walk over the raw keyed sets of an `online-indexed` space, its subject read by the owner from the key alone; an orphan removed, with no step elsewhere. An `online-keyed` space answers `migrated` with none, its reading not called.

## Invariants
- A set is read strictly first: one with any malformed part stops the space (`unreadable: …`). An indexed set is its raw value whole in an envelope, both lists and every member's end as they were, nothing rebuilt and no cap applied again, keeping its end.
- A record is migrated already only where its envelope is listed in its subject's bucket (`online-indexed`) or witnessed (`online-keyed`), never by its shape alone: a raw record of an envelope's shape is wrapped whole. In a sets space such a value is no set, and stops the space as `unreadable`.
- Every outcome, a skip and an absence included, is decided in one confirmed change holding the record as read, never on reads alone, which a failover can take back: first whether it is migrated already or gone, then the owner's answer, with the envelope's own listing or witness held too, so a removal never takes what another run migrated meanwhile. A record written is written with its bucket entry or witness, its value and end kept; one changed is read again, up to 8 times, then unavailable.
- Where `elsewhere` is given, it runs for each orphan, on the value the first confirmed change held, before the removal; the removal still holds that value, so a record changed meanwhile is read again and the step run again; a throw stops the space (`elsewhere: <its type>`), removing nothing more. What it keeps, and that it keeps it durably and confirmed, is the owner's.
- Only `orphan` removes a record. `unreadable`, a failed lookup among them, stops the space and removes nothing more; so does a record of an `online-keyed` space read as another subject's than its key.
- A `bounded` space has nothing to index; a walk whose server changes starts over, at most 8 times.
- It runs in the maintenance window after `indexed` and before erasure is enabled (account erasure §5.1): no owner writes and no erasure run beside it.

## Depends on
- `erasure-extensions` (the report, `SubjectReading`, `SetReading`, `Elsewhere`, `Walk`), `kernel` (Unavailable), `records` (`changeRecords`, the keyed set codec's strict read), `store`; internal modules `envelope`, `index`
