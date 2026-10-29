# settle

Internal module of `refresh`: the stores, the revoker, and what revokes families from outside.

## Responsibilities
- Revokes a family and the access tokens it issued, and finishes a revocation left halfway by a sweep.

## Not here
- When a family is revoked (`grant`, `lineage`, the contributions below).

## Offers
- `settlingIn` (the build context) → the stores, the revoker and the family lifetime, refusing where access tokens cannot be revoked; `revocableOver` → `token-control`'s revocable kind; `participantOver` → `session-participants`' participant.

## Invariants
- Revocation lists the family, writes the mark (even with no record, so a family mid-start never comes alive), revokes its access tokens, then unlists it.
- What a list's cap pushes out is revoked, logged, and a failure.
- A revocation `token-control` asks of a family already marked is finished before it is answered (`done`), whoever asks, so a retry after an outage never answers revoked while its access tokens are not; another client's live family is left alone and answered `done` too.

## Depends on
- `tokens` (revoking and its references), `kernel`; the package's records and store interfaces
