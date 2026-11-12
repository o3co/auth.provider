# erasure

Internal module of `mfa`: erasing a subject's factor lists and claims, and migrating its space, through the factor store's ports.

## Responsibilities
- Is mfa's eraser, `mfa`, as its space's `erasedBy` names it, and states whether it can erase.

## Not here
- What a store's erasure removes, and the tombstone (`subject-records`, behind the store's ports). The ports' statement (`records`). When an eraser runs, and the run's report (`account-erasure`).

## Offers
- `factorEraser` (the factor store) → an `Eraser`: `online` erases the subject's lists and claims; `window` each subject in turn; `migrate` by `factorSubjectOf`. `logoutGaps` is 0: it removes no session.
- `factorSubjectOf` (the store, to read a claim's list) → a record's subject, as the migration reads it.

## Invariants
- A list, read strictly through `records`' `strictListOf`, is its subject's where the subject it holds names its key (`s-` and the base64url SHA-256 of the subject). One of another shape, a missing factors array among them, is unreadable as malformed.
- A list holding no subject, otherwise a list, which only 0.18.0-rc.1 wrote, is unreadable, the reason naming its key and its remedies: the subject's next proof or change of a factor rewrites it; mfa-reset of the subject rewrites it by clearing its factors, to be bound again; or erasure stays off.
- A claim is its list's subject's where that list holds its factor. A claim is an orphan where its list, read during the migration's maintenance window (AE §5.1), does not hold its factor. No provider writes then, so that reading stands until the claim is removed: the claim states something false, and removing it loses nothing.
- A claim whose list is gone or malformed, a record of another shape, or a read that fails is unreadable, never an orphan.
- `erasable` only where the store offers `erase` and `migrate`; otherwise empty reports.

## Depends on
- `erasure-extensions` (the eraser and its readings); internal module `records` (`recordKindOf`, `strictListOf`, `strictClaimOf`, `listKeyOf`); the package's store interface.
