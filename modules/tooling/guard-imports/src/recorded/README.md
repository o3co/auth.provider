# recorded

Internal module of `guard-imports`: G30, that an audit event is recorded only through its declarations.

## Responsibilities
- Finds, in shipped code, each call that records on the audit contract itself rather than through the wrapper its declarations give.

## Not here
- Which events a package records, and their attributes: each package's `./audit-events`. Whether the audit event reference is current: `create-app`, which generates it.

## Offers
- `declaredRecordRules` (G30).

## Invariants
- The package the `./audit-events` exports declare through is read from their imports, never named here; a package depending on it is read, the package itself, its `./testing` and tests are not.
- Each `record` call is resolved by type: one resolving to a `record` declared on an interface of that package counts, through a `Pick` too; a value of no known type (`any`) resolves to nothing and is missed, not reported.

## Depends on
- `typescript`.
