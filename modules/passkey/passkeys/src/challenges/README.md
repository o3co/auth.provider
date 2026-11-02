# challenges

Internal module of `passkeys`: the challenges that registrations and assertions answer.

## Responsibilities
- Keeps each challenge made for a registration or an assertion, with when it was made, until it is taken or its lifetime ends.

## Not here
- Making a challenge (`webauthn`'s ceremonies). The requester's digest, and whether it matches (the package's assertion). Where challenges are kept (the challenge store).

## Offers
- `keptChallenges` (the challenge store, `kernel`'s clock, the lifetime) → `open` (a challenge and its purpose) and `take` (a challenge → its purpose and when it was made, or none).

## Invariants
- A challenge is 32 bytes in canonical form; any other is taken as none, the store unasked.
- Opening a challenge already kept is unavailable: 32 random bytes meeting another cannot be told from a broken place.
- Taking puts a mark in its place, which stays for the rest of its lifetime, so a challenge is taken once.
- A challenge ends on `kernel`'s clock, whatever the store's expiry, as a late write gives it the store's full lifetime again.
- The purpose is kept as given: an assertion's asker (`by`) and its id's digest, which the package's assertion makes and compares apart. A format 1 assertion names no asker; a format 1 registration reads as one of format 2.
- A record in another shape reads as none.

## Data
- A challenge's record (`v` 2, its kind, the subject or the asker and its id's digest, and when it was made; `v` 1, the format before, read), then the taken mark in its place, through the challenge store.

## Depends on
- `kernel` (`Unavailable`), `webauthn` (the canonical form); the package's store interface
