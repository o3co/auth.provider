# upstream-account

Internal module of `federation-grants`: whose upstream account a connection reached.

## Responsibilities
- Decides whether the upstream account a callback's login names is one the grant's subject may connect: the one the grant already holds, the one its intent expects, and, under the identity check, one no other user holds.
- Holds the identity check (`identity-check`) as the one place that reads it.

## Not here
- The callback and the activation (`connect`). Who holds an upstream identity (`users`).

## Offers
- `upstreamAccountWith` (`users`' lookup by upstream identity, the identity check) and `upstreamAccountOver` (the build context) → `refusal` (grant, intent, IdP, the account reached: `account_mismatch`, `identity_unverifiable`, `identity_conflict`, or none) and `check`, the identity check made, as an activation's audit names it.

## Invariants
- An account other than the grant's recorded one, or than its intent's expected subject, is `account_mismatch`.
- Under `required`, an account another user holds is `identity_conflict`; one nobody holds, or the subject's own, passes. Under `none`, nobody is asked.
- Any failure of the lookup reads as `identity_unverifiable`, an unavailable ledger and any other throw alike.

## Depends on
- `users` (the lookup by upstream identity), `kernel` (the build context); the package's section
