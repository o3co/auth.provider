# grants

Internal module of `consent`: each subject's grants, per client, as the grant store keeps them.

## Responsibilities
- Reads and writes the grant records.

## Not here
- Whether to ask, and the consent page (the package and `page`).

## Offers
- `grantsOver` (the build context) → `grantsWith` (the grant store) → `rangeFor`, `covers` and `widen`.

## Invariants
- `covers` needs a record, for an empty range too.
- A write is an update from what the record holds, or a save; another request's save between them is widened in turn, and one gone by then is `Unavailable`.

## Data
- Grants: one record per subject and client, distinct and sorted, kept without end.
- A client registered again under the same id keeps its grants.

## Depends on
- `kernel` (the build context, `Unavailable`); the package's grant store interface
