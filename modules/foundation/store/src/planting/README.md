# planting

Internal module of `store`: a value written at a key as an earlier version, or another writer, left it, for tests.

## Responsibilities
- Writes one value at one key as one batch with no conditions, carrying the subject writer, so a space of the four categories `checks` names takes it as any other (`plantValue`).

## Not here
- A record in records' layout: `records`' `./testing`, over this.
- The writer's value: the internal module `writer`.

## Offers
- `plantValue(store, key, value, expiry)`, through `./testing` alone.

## Invariants
- Reached from `./testing` alone: shipped code changes subjects' data through `subject-records`.

## Depends on
- `store`'s contract; the internal module `writer`.
