# links

## Responsibilities
- Answers by upstream identity, and links and unlinks, in one of two ways users chooses at boot: through users' link store, or as a ledger that looks users up by upstream identity holds them.

## Not here
- Checking the subject and upstream parts given, and which way is chosen: users' own.

## Offers
- `keptLinks(source, links)`: links written through the link store, below the source's own.
- `linkSubjectOf` (a link record as stored) → whose it is, for the one migration: the subject it holds; a trace an unlink left, holding no subject, an orphan by its shape; any other shape unreadable.
- `ledgerLinks(source)`: the source's links alone; `link` answers already or conflict, and `unlink` fixed or none.

## Invariants
- A link of the source (a settings link) wins over a written one of the same upstream identity, which stays hidden and cannot be unlinked (unlink answers fixed); taking the identity out of the settings lets the written link take effect again.
- A written link is taken by one subject at most, also when two ask at once, and finds its subject's user, or none where the source answers none; unanswerable is unavailable.
- `ledgerLinks` reads and writes no link store.

## Depends on
- users' contract and store interfaces; internal module `stores` (`keptFor`); `erasure-extensions` (`SubjectOf`, for its reading)
