# migrate

Internal module of `subject-records`: the one migration of a space's records written before they were indexed.

## Responsibilities
- Puts each raw record of a space into its subject's index, or removes it where its owner proves it has none, once records are indexed.

## Not here
- Whose a record is: the owner's `SubjectReading`. Walking the space and when the migration runs: account erasure's tool, which hands in the `Walk`. Keyed sets: their own migration, later.

## Offers
- `migrateRecords` (a place, a `Walk`, the owner's `SubjectReading`, a signal) → a `MigrationReport`: `migrated` with what was indexed and removed, or `stopped` with why (`not-indexed`, `aborted`, `unavailable`, `index-unreadable`, `walk-unsteady`, `unreadable: …`, `a record keyed by another subject`).

## Invariants
- A record is migrated already only where its envelope is listed in its subject's bucket (`online-indexed`) or witnessed (`online-keyed`), never by its shape alone: a raw value of an envelope's shape is wrapped whole.
- Every outcome, a skip and an absence included, is decided in one confirmed change holding the record as read, never on reads alone, which a failover can take back: first whether it is migrated already or gone, then the owner's answer, with the envelope's own listing or witness held too, so a removal never takes what another run migrated meanwhile. A record written is written with its bucket entry or witness, its value and end kept; one changed is read again, up to 8 times, then unavailable.
- Only `orphan` removes a record. `unreadable`, a failed lookup among them, stops the space and removes nothing more; so does a record of an `online-keyed` space read as another subject's than its key.
- A `bounded` space has nothing to index; a walk whose server changes starts over, at most 8 times.
- It runs in the maintenance window after `indexed` and before erasure is enabled (account erasure §5.1): no owner writes and no erasure run beside it.

## Depends on
- `erasure-extensions` (the report, `SubjectReading`, `Walk`), `kernel` (Unavailable), `records` (`changeRecords`), `store`; internal modules `envelope`, `index`
