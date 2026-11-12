# ports

Internal module of `passkeys`: the passkey store's ports, as passkeys uses them.

## Responsibilities
- States which ports a passkey store must offer, and gives `joint`'s writes the store's change of both spaces as one in the words they ask it in, whichever port the store offers.

## Not here
- The record shapes and their keys (`records`). What a write changes (`joint`). The ports' types (the package's store interface).

## Offers
- `portsRefused` (the passkey store) → why its ports cannot be used, or none: the one statement, which boot refuses by.
- `togetherOf` (the passkey store) → its change of both spaces as one, as `joint`'s writes ask it.

## Invariants
- A store offers exactly one of `updateAsOne` and `updateTogether`, and each space's `erase` and `migrate`, all four or none.
- Through `updateAsOne`, a record none holds is created for the subject it is written for, and a held one moved to it, a change where it is that subject's already; the subject is the one a passkey's record names, or a holder's own. A refusal is unavailable, nothing written.
- A holder written for no subject is unavailable: every write passkeys makes names one.

## Depends on
- `kernel` (`Unavailable`, through `records`); the internal module `records` (the shapes read); the package's store interface
