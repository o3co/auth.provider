# walk

Internal module of `records`: a walk of a space's records over the walk a maintenance tool hands in.

## Responsibilities
- Hands a caller each record's value a walk of the space meets, and says whether it finished.

## Not here
- What a value holds and what the caller decides from it: the caller's. Where the walk comes from and when it runs: the maintenance tool's.

## Offers
- `walkRecords` (a place, a walk, a visitor, a signal) → `walked`, `stopped` (the visitor answered false), or `unfinished` with `walk-unsteady`, `aborted` or `unavailable`; the builders offer it as `walk`.
- `Walk`, declared by its shape alone: `sweep(space, cursor?)` answering the store's keys, a cursor and the server a page ran on. `Walked`, `Unfinished`.

## Invariants
- A page from another server continues no walk: it starts over from the first page, at most 8 times, then answers `walk-unsteady`. A walk never ends at a change of server.
- Only the keys of the place's space and its records are read; another space's, or another name's, are passed over. A record gone since its page was taken is passed over.
- Values are read as the space's own reads are, confirmed only where it declares confirmed reads, and never opened. A record met twice is handed over twice.
- A store that cannot tell answers `unavailable`; the caller's signal answers `aborted`. Neither is a finished walk.

## Depends on
- `kernel` (`Unavailable`), `store` (`Json`); the package's `Place`.
