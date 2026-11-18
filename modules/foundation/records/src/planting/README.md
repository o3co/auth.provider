# planting

Internal module of `records`: a record written in records' key layout as an earlier version left it, for tests.

## Responsibilities
- Writes a value as the record a target names, at records' key (`changeRecords.keyOf`), ending after a lifetime as records' changes end one, or never (`plantRecord`). A target is any records takes: by key (a keyed set's too, `set: true`), under a secret, or by the name kept for a secret (`secretName`).

## Not here
- The write itself, carrying the subject writer: `store`'s `./testing` (`plantValue`).

## Offers
- `plantRecord(target, value, lifetimeMs?)`, through `./testing` alone.

## Invariants
- Reached from `./testing` alone: shipped code changes records through `changeRecords` and the builders.

## Depends on
- `store`'s `./testing`; the internal modules `together` and `writing` (`expiryOf`).
