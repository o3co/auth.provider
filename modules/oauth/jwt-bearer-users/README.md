# jwt-bearer-users

## Responsibilities
- Joins `jwt-bearer` and `users`: resolves the subject a linked issuer's signer stands for through `users`, and declares the linked issuers' IdP names to `users`.

## Not here
- Reading and verifying assertions, and which issuers are linked: `jwt-bearer`.
- Who a user is and how an upstream identity finds one: `users`.

## Offers
- Composition definition only: a contribution at `jwt-bearer`'s `linkedSubjects`, and one at `users`' `upstreamNames`. It joins an app composing both, and no other.

## Invariants
- A linked signer stands for the subject of the user `users` finds by the issuer's IdP name and the signer's `sub`; none where `users` finds none, and unavailable where it cannot tell.
- Every linked issuer's IdP name is declared to `users` with the issuer, in one list, an empty one where none is linked, so `users` refuses boot on a name standing for two issuers.

## Depends on
- `kernel`, `jwt-bearer`, `users`
