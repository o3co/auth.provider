# mfa-email-proof

## Responsibilities
- Contributes the proof of the account's address asked before a first binding (`account-email`): a long code mailed there, by `mfa-email`'s rules for the address and the code.

## Not here
- Whether a proof is asked, and the pass it gives (`mfa-binding-proof`). The address users stands behind, mailing a code and its forms (`mfa-email`, over `mail`, `users` and `subject-attributes`). The account's addresses (`users`).

## Offers
- Contribution to `mfa-binding-proof`'s binding proofs (boot is refused without `mfa-binding-proof` composed): `account-email`, available while the account has an address `mfa-email` takes; a 16-character code good for ten minutes at most, mailed under `mfa-email`'s purpose `mfa-email.proof`.
- A proof that passes tells `users` the address is the subject's (`verifiedContact`); past the contacts `users` keeps, it still passes, logging `mfa-email.contact_not_kept` without the address.

## Invariants
- The address is the one `mfa-email` takes for the account (its claimed contact, else a login `users` vouches for), never an upstream's; with none, the proof is not available and nothing is sent.
- What a proof keeps that is there but cannot be read is a failure (unavailable), never a wrong code.
- A code is compared in constant time, and refused past its end.

## Depends on
- `kernel`, `mfa-binding-proof`, `mfa-email` (the address, mailing a code, the long code, the purpose), `users` (verified contacts)
