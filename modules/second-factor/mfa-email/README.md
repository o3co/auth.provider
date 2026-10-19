# mfa-email

## Responsibilities
- Contributes a code sent by mail as a kind of second factor (`email`), and the proof of the account's address asked before a first binding (`account-email`).

## Not here
- Delivering mail and its limits (`mail` and its sender). The account's address (`users`). Keeping factors, challenges and transactions (`mfa`, `mfa-flows`).

## Offers
- Contribution to `mfa`'s factor kinds: `email`, amr `email`, guessable, counting.
  - Enrolment: a 16-character code (Crockford's base32, 80 bits) mailed to the address the account states; its first proof is that code.
  - Challenge: six digits mailed to the factor's address, good until the earlier of `code-lifetime` and the end the caller gives.
  - Both show `{sent_to, expires_in}`: the address's first character and its domain, and the seconds the code lives.
- Contribution to `mfa-binding-proof`'s binding proofs (boot is refused without `mfa-binding-proof` composed): `account-email`, available while the account states an address; a 16-character code good for ten minutes at most. A proof that passes tells `users` the address is the subject's (`verifiedContact`).
- Mail purposes `mfa-email.enrollment`, `mfa-email.login`, `mfa-email.proof`, taking `code` and `minutes`; `mfa-email-wording` words them.
- `purposes` and their type `Purpose`, for the module that words them.
- Operator section: `adds-second-factor` (whether a proof adds `mfa`; default false), `code-lifetime` (1m–30m, default `10m`, written with its unit).

## Invariants
- The address is the account's claimed `email` contact in `users`, in NFC and `mail`'s canonical form (its domain in ASCII, lower case), so one mailbox has one form; none or one `mail` does not take refuses the kind.
- Without one, it is the `email` the login gave when `users` vouches for it (an outside ledger's answer): a held login's as `mfa` passes it on, `vouched`, or the session's by `subject-attributes`. An upstream's claim is never read. With neither, the kind refuses, the proof is not available, and a factor's challenge is `contact-changed`, as when the address changes.
- Before anything is sent, an address the subject already holds a factor at is a duplicate; another subject's factors are not compared.
- A challenge to an address the account no longer states (changed or gone) is refused with the reason `contact-changed`, and nothing is sent.
- A stored secret or kept code that is there but cannot be read is a failure (unavailable), never a refusal or a wrong code: nothing is sent and no attempt is spent.
- A code is kept only sealed by `mfa`, compared in constant time, and refused past its end. A sender's limit is `limited`.
- A long code is read from ASCII letters, digits, hyphens and spaces only, in any case, O read as 0 and I or L as 1; six digits are read with white space around them only (as `trim` takes it).

## Depends on
- `kernel`, `mail`, `mfa-extensions` (the kind's contract), `mfa` (composed for it: it stays among this package's dependencies, so adding this kind composes `mfa`), `mfa-binding-proof`, `users` (claimed and verified contacts), `subject-attributes` (a session's vouched login attributes)
