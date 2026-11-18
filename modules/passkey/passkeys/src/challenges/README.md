# challenges

Internal module of `passkeys`: the challenges that registrations and assertions answer.

## Responsibilities
- Keeps each challenge made for a registration or an assertion, with when it was made, until it is taken or its lifetime ends: a registration's in the registration challenge store where composed, for its subject; every other in the challenge store.

## Not here
- Making a challenge (`webauthn`'s ceremonies). The requester's digest, and whether it matches (the package's assertion). Where challenges are kept (the challenge stores).

## Offers
- `keptChallenges` (the challenge store, `kernel`'s clock, the lifetime, the registration challenge store where composed) → `open` (a challenge and its purpose) and `take` (a challenge and the kind its caller answers → its purpose and when it was made, or none).

## Invariants
- A challenge is 32 bytes in canonical form; any other is taken as none, the store unasked.
- A challenge found where its caller's kind is looked up, but made for another kind, is taken there all the same, so it is answered once, and answers none. A registration's kept in the registration challenge store is not looked up for an assertion, so it is not taken.
- Opening a challenge already kept is unavailable: 32 random bytes meeting another cannot be told from a broken place. So is opening a registration's for a subject its store fences.
- A registration's challenge is taken from the registration challenge store, and from the challenge store only where that one holds none, as a 0.19 node opened it there; a taken mark is an answer.
- Taking puts a mark in its place, which stays for the rest of its lifetime, so a challenge is taken once.
- A challenge ends on `kernel`'s clock, whatever the store's expiry, as a late write gives it the store's full lifetime again.
- The purpose is kept as given: an assertion's asker (`by`) and its id's digest, which the package's assertion makes and compares apart. Redeemed by the same requester alone: another module's with the same id is `challenge`, after it is taken. A format 1 assertion, as 0.18 opened them, names no asker, and is read, taken and refused as `challenge`; a format 1 registration reads as one of format 2.
- A requester's id is never a subject's: an assertion's challenge holds no subject's data, so the challenge store is declared holding none.
- A record in another shape reads as none.

## Data
- A challenge's record (`v` 2, its kind, the subject or the asker and its id's digest, and when it was made; `v` 1, the format before, read), then the taken mark in its place, through the store it is kept in.

## Deprecated
- Registration challenges in the challenge store, read there where the registration challenge store holds none, and kept there where none is composed (passkeys' eraser then answers `erasable: false`); removed in 0.22, when the registration challenge store is required.

## Depends on
- `kernel` (`Unavailable`), `webauthn` (the canonical form); the package's store interfaces
