# planting

Internal module of `records`: a record written in records' key layout as an earlier version left it (a record as 0.19 wrote it, say), for tests.

## Responsibilities
- Writes a value as the record a target names (by key, or under a secret), at records' key (`changeRecords.keyOf`), ending after a lifetime or never (`plantRecord`).

## Not here
- The write itself, carrying the subject writer: `store`'s `./testing` (`plantValue`).

## Offers
- `plantRecord(target, value, lifetimeMs?)`, through `./testing` alone.

## Invariants
- Reached from `./testing` alone: shipped code changes records through `changeRecords` and the builders.

## Depends on
- `store`'s `./testing`; the internal module `together`.
