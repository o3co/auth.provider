# grants

Internal module of `consent`: each subject's grants, per client, as the grant store keeps them.

## Responsibilities
- Reads and writes the grant records, and decides whether one counts for a client now.

## Not here
- Whether to ask, and the consent page (the package and `page`). What a client's source says of its description (the source, through the section's `under`).

## Offers
- `grantsOver` (the build context) → `grantsWith` (the grant store) → `rangeFor`, `covers` and `grant` (a client, a subject, a range), and `keep` (a client's id, a subject, a range, what it is agreed under).

## Invariants
- A grant counts for a client the operator registered whatever it holds under; for any other client, only where it holds under the value that client's section says now.
- A client from another source whose section says no `under` is never covered: nothing shows what it was agreed under.
- A grant that does not count answers an empty range and covers nothing, an empty range included; `covers` needs a record that counts.
- `keep` under a value the record does not hold replaces the range rather than adding to it, so no range agreed under another description comes back. Under no value it adds, and leaves the record under none.
- A record of a format this module does not read is no grant: it counts for no client, and the next write replaces it.
- A write is an update from what the record holds, or a save; another request's save between them is changed in turn, and one gone by then is `Unavailable`.

## Data
- Grants: one record per subject and client, kept without end, with a range distinct and sorted.
- Format 2, written: `{ format: 2, range, under? }`. Format 1, read: the range alone, which holds under no value.
- A client registered again under the same id keeps its grants.

## Depends on
- `clients` (the client type), `kernel` (the build context, `Unavailable`); the package's section and grant store interface
