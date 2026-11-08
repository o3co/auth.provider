# mfa-email-proof

## Responsibilities
- Contributes the proof of the account's address asked before a first binding (`account-email`): a long code mailed there under its own purpose, by `account-mail-code`'s rules for the address and the code.

## Not here
- Whether a proof is asked, and the pass it gives (`mfa-binding-proof`). The address users stands behind, mailing a code and its forms (`account-mail-code`, over `mail`, `users` and `subject-attributes`). The wording of its mail (`mfa-email-proof-wording`, which a deployment replaces). The account's addresses (`users`).

## Offers
- Composed on its own: it opts in, so the full template takes it only where it is added or a composed module needs it.
- Contribution to `mfa-binding-proof`'s binding proofs (boot is refused without `mfa-binding-proof` composed): `account-email`, available while the account has an address `account-mail-code` takes; a 16-character code good until the transaction it is asked in ends, mailed under its purpose `mfa-email-proof.account-email`, declared to `mail`.
- `purposes` (`mfa-email-proof.account-email`) and their type `Purpose`, for the module that words them; `proofName` (`account-email`), for the modules that ask for the proof.
- A proof that passes tells `users` the address is the subject's (`verifiedContact`); past the contacts `users` keeps, it still passes, logging `mfa-email.contact_not_kept` without the address.

## Invariants
- The address is the one `account-mail-code` takes for the account (its claimed contact, else a login `users` vouches for), never an upstream's; with none, the proof is not available and nothing is sent.
- What a proof keeps that is there but cannot be read is a failure (unavailable), never a wrong code.
- A code is compared in constant time, and refused past its end.

## Depends on
- `kernel`, `account-mail-code` (the address, mailing a code, the long code), `mail` (its purpose), `mfa-binding-proof`, `users` (verified contacts)
