# settle

Internal module of `refresh`: the stores, the revoker, and what revokes families from outside.

## Responsibilities
- Revokes a family by its mark, links each access token to its family, and withdraws an access token a failed round issued.

## Not here
- When a family is revoked (`grant`, `lineage`, the contribution below). Refusing a marked family's tokens (`lineage`'s access condition, the grant).

## Offers
- `settlingIn` (the build context) → the stores, the revoker and the family lifetime, refusing where access tokens cannot be revoked; `revocableOver` → `token-control`'s revocable kind.

## Invariants
- Revocation is the mark alone, written even with no record, so a family mid-start never comes alive; its access tokens are not revoked by id, nor is it listed or swept.
- A revocation `token-control` asks of a family already marked is answered `done`, whoever asks; another client's live family is left alone and answered `done` too.

## Deprecated
- The store interfaces for each session's families, each family's access tokens and the families to revoke, with their needs and their parts of the contract test (`./testing`): neither read nor written. A later release removes them.

## Depends on
- `tokens` (withdrawing a token, and its references), `kernel`; the package's records and store interfaces
