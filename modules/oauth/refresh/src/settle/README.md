# settle

Internal module of `refresh`: the stores, the revoker, and what revokes families from outside.

## Responsibilities
- Revokes a family by its mark, links each access token to its family, and withdraws an access token a failed round issued.

## Not here
- When a family is revoked (`grant`, `lineage`, the contribution below). Refusing a marked family's tokens (`lineage`'s access condition, the grant).

## Offers
- `settlingIn` (the build context) → the stores, the revoker and the family lifetime, refusing where access tokens cannot be revoked; `revocableOver` → `token-control`'s revocable kind.

## Invariants
- Revocation is the mark alone; its access tokens are not revoked by id, nor is it listed or swept. No record: gone by its end, by its subject's erasure, or never founded; each reads as ended, and nothing is marked. Until 0.22 a mark is still saved there, through the store's deprecated `unowned` where offered, for a 0.19 founder that writes a redemption's link before the family; `closed` marks nothing.
- A revocation `token-control` asks of a family already marked writes the mark again, confirmed, before it is answered `done`, whoever asks, as one read before its write was confirmed could be lost in a failover; another client's live family is left alone and answered `done` too.

- A family is saved for its subject. A save the family store answers `erased`, its subject's erasure fencing it, is unavailable, never `exists`, and no family starts; a retry never passes. The family store's `erase` and `migrate` are optional in 0.20 and required in 0.22.

## Deprecated
- The store interfaces for each session's families, each family's access tokens and the families to revoke, with their needs and their parts of the contract test (`./testing`): neither read nor written. A later release removes them.

## Depends on
- `tokens` (withdrawing a token, and its references), `kernel`; the package's records and store interfaces
