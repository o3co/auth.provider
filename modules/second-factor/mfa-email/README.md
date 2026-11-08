# mfa-email

## Responsibilities
- Contributes a code sent by mail as a kind of second factor (`email`).

## Not here
- Delivering mail and its limits (`mail` and its sender). The address `users` stands behind, mailing a code and its forms (`account-mail-code`). The account's address (`users`). Keeping factors, challenges and transactions (`mfa`, `mfa-flows`). The proof of the account's address before a first binding (`mfa-email-proof`).

## Offers
- Contribution to `mfa`'s factor kinds: `email`, amr `email`, guessable; it counts toward a required second factor only where its proof adds `mfa` (`adds-second-factor`, which every start warns of: `mfa-email.counts_as_second_factor`), and is otherwise a way back only, under `mfa.mode = optional`: under `required`, `mfa` does not take it.
  - Enrolment: a 16-character code (Crockford's base32, 80 bits) mailed to the address the account states; its first proof is that code.
  - Challenge: six digits mailed to the factor's address, good until the earlier of `code-lifetime` and the end the caller gives.
  - Both show `{sent_to, expires_in}`: the address's first character and its domain, and the seconds the code lives.
- Boot is refused where no binding proof `account-email` is composed (`mfa-email-proof`'s), or where `mfa-binding-proof`, which hears it, is not: a code by email comes with the proof of the account's address, so a first factor is never bound unproved.
- Mail purposes `mfa-email.enrollment` and `mfa-email.login`, taking `code` and `minutes`; `mfa-email-wording` words them.
- `purposes` and their type `Purpose`, for the module that words them.
- Operator section: `adds-second-factor` (whether a proof adds `mfa`, and so whether the factor counts; default false), `code-lifetime` (1m–30m, default `10m`, written with its unit).

## Invariants
- The address is the one `account-mail-code` takes for the account (its claimed contact in one form, else a login `users` vouches for), never an upstream's; with none, the kind refuses, and a factor's challenge is `contact-changed`, as when the address changes.
- Before anything is sent, an address the subject already holds a factor at is a duplicate; another subject's factors are not compared.
- A challenge to an address the account no longer states (changed or gone) is refused with the reason `contact-changed`, and nothing is sent.
- A stored secret or kept code that is there but cannot be read is a failure (unavailable), never a refusal or a wrong code: nothing is sent and no attempt is spent.
- A code is kept only sealed by `mfa`, compared in constant time, and refused past its end. A sender's limit is `limited`.

## Depends on
- `kernel`, `mail`, `account-mail-code` (the address, mailing a code, its forms), `mfa-extensions` (the kind's contract), `mfa-email-proof` (`proofName`), `users` (claimed contacts), `subject-attributes` (a session's vouched login attributes)
- Composed for it, so adding this kind composes each: `mfa`; `mfa-binding-proof` (its binding proofs, read to check `account-email` is composed; the proof's host); `mfa-email-proof`.
