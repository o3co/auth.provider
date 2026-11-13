# granting

Internal module of `jwt-bearer`: the grant itself, once boot has checked what it is built from.

## Responsibilities
- Turns an assertion into a token: sorts it by type, sends a delegated issuer's to its delegate, verifies the rest against the trusted issuers, binds it to its client, holds it to its conditions, resolves its subject, and issues once its single use is spent.
- Identifies the client of a request naming none, where an entry has a `client`.

## Not here
- The boot checks and the refusals they make: the package's (`module.ts`). Reading the issuers and their keys (`issuers`), an assertion's signature and claims (`assertion`), an ID-JAG's rules (`id-jag`), a delegate's answer (`delegated`), an entry's conditions (`conditions`), how long a spent `jti` is kept (`policy`).

## Offers
- `grantingWith` (the issuer, the entries, the trusted issuers, their ledgers, the delegates, the store of spent assertions, the revocation boundaries, the clock skew, the linked subjects' resolver if one, the clock, the log) → the grant, its type left to the package.

## Invariants
- What an assertion becomes, and each refusal on the way: the package's card.
- An assertion's `jti` is once only: spent in its issuer's ledger where one is contributed, else through the store interface, by a hash of the `iss` as sent and the `jti`, unless spent already. In the store, a self-issued signer's assertions are spent apart from its issuer's own; a ledger keeps them apart only where it is told the `iss`, and one that is not counts both as one, which refuses more and never lets a reuse through.
- A ledger is asked with the `iss` and `jti` as sent, the `exp`, and the time it must stay used until (`policy`'s, set by no setting). A throw, or an answer neither `first` nor `replayed`, is unavailable, issuing nothing; the store is never written or read for that issuer, so a ledger out never falls back to it. One whose answer is lost may stay used: the client signs another.
- A spend is read at its boundary by the package's `spentAt`: any throw but Unavailable, and any answer the ledger or the delegate does not give, is Unavailable.

## Depends on
- `client-allowance`, `grants`, `kernel` (the log), `subject-revocation` (the boundaries); the package's contract, `spentAt` and the internal modules named above.
