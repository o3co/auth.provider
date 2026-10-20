# lineage

Internal module of `refresh`: the `lineage` contract, and `tokens`' access condition on a family's end.

## Responsibilities
- Answers an access token's family, adopts tokens into a live family, and starts families bound to no session.

## Not here
- Revoking (`settle`). Founding a family (`grant`'s founding).

## Offers
- `lineageIn` (the build context) → the contract; `conditionOver` → the access condition, built on the stores alone, as `tokens` asks it while it is being built itself; `familyReader` (stores, clock) → a token's family and whether it has ended; `familyTie` (the contract) → the `family` tie.

## Invariants
- `of` answers only for a token the caller verified, reads the record every time, and names the token asked for, never the family.
- An end racing an adoption is run again.

## Depends on
- `client-allowance`, `kernel`; `grant`'s founding, the package's records and store interfaces
