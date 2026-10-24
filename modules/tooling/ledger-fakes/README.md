# ledger-fakes

## Responsibilities
- Plays the operator's HTTP ledgers for tests and conformance scenes: the user ledger, and the witness ledgers of mfa and passkeys, each speaking the wire as `ledger-wire` words it.

## Not here
- The wire's words: `ledger-wire`. Serving a fake over HTTP, and pointing an app's settings at it: the scene's (`conformance`'s parties, a test's server).
- Anything a product reads: it is verification, unpublished.

## Offers
- `usersLedger` (users): the password call and the lookups by subject and by upstream identity, for the users given, each with any upstream identity linked to it (`LedgerUser`).
- `mfaWitnessLedger` (`withdraw: false` plays a ledger with no withdraw route, and serves no URL for it) and `passkeyWitnessLedger`.
- Each a `FakeLedger`: its `answer` to a `LedgerCall` (a `LedgerAnswer`, none for a call not its own), its `urls` at a base (each call at `ledger-wire`'s route), and its `credential`.

## Invariants
- A call of its own without its credential, or not a POST, is answered a bare `404`, so a wrong set-up shows; a user ledger's lookup that finds no user says so (`404` with `not_found`), and a password call that finds none answers `401`.
- A witness ledger keeps one mark per subject, set only where none is, withdrawn only by its token; a write answers `204`.
- Each read names the mark's token. mfa's also clears the mark whatever it holds; the passkey witness keeps no clear.
- Each ledger draws a credential of its own.

## Depends on
- `ledger-wire` (the wire's words).
