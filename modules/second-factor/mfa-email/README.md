# mfa-email

## Responsibilities
- Contributes a code sent by mail as a kind of second factor (`email`), and owns how a code is mailed to the account's address, which `mfa-email-proof`'s proof before a first binding uses too.

## Not here
- Delivering mail and its limits (`mail` and its sender). The account's address (`users`). Keeping factors, challenges and transactions (`mfa`, `mfa-flows`). The proof of the account's address before a first binding (`mfa-email-proof`).

## Offers
- Contribution to `mfa`'s factor kinds: `email`, amr `email`, guessable; it counts toward a required second factor only where its proof adds `mfa` (`adds-second-factor`, which every start warns of: `mfa-email.counts_as_second_factor`), and is otherwise a way back only.
  - Enrolment: a 16-character code (Crockford's base32, 80 bits) mailed to the address the account states; its first proof is that code.
  - Challenge: six digits mailed to the factor's address, good until the earlier of `code-lifetime` and the end the caller gives.
  - Both show `{sent_to, expires_in}`: the address's first character and its domain, and the seconds the code lives.
- Boot is refused where no binding proof `account-email` is composed (`mfa-email-proof`'s), or where `mfa-binding-proof`, which hears it, is not: a code by email comes with the proof of the account's address, so a first factor is never bound unproved.
- Mail purposes `mfa-email.enrollment`, `mfa-email.login`, `mfa-email.proof`, taking `code` and `minutes`; `mfa-email-wording` words them.
- `purposes` and their type `Purpose`, for the module that words them.
- For a proof that mails a code to the same address by the same rules: `mailedCodes` (mail, users, a session's attributes, the clock) → `addressNow` (subject, where asked from → the address, as the invariants below choose it), `send` (purpose, address, code, end → sent with what to show and keep / limited) and `matches` (kept code, typed → whether it is the code, before its end); `longCode` and `readLongCode`.
- `mailedCodesIn` (the build context): the same, taking them from the assembly; a module calling it names `mailedTakes` in its takes.
- Operator section: `adds-second-factor` (whether a proof adds `mfa`, and so whether the factor counts; default false), `code-lifetime` (1m–30m, default `10m`, written with its unit).

## Invariants
- The address is the account's claimed `email` contact in `users`, in NFC and `mail`'s canonical form (its domain in ASCII, lower case), so one mailbox has one form; none or one `mail` does not take refuses the kind.
- Without one, it is the `email` the login gave when `users` vouches for it (an outside ledger's answer): a held login's as `mfa` passes it on, `vouched`, or the session's by `subject-attributes`. An upstream's claim is never read. With neither, the kind refuses, and a factor's challenge is `contact-changed`, as when the address changes.
- Before anything is sent, an address the subject already holds a factor at is a duplicate; another subject's factors are not compared.
- A challenge to an address the account no longer states (changed or gone) is refused with the reason `contact-changed`, and nothing is sent.
- A stored secret or kept code that is there but cannot be read is a failure (unavailable), never a refusal or a wrong code: nothing is sent and no attempt is spent.
- A code is kept only sealed by `mfa`, compared in constant time, and refused past its end. A sender's limit is `limited`.
- A long code is read from ASCII letters, digits, hyphens and spaces only, in any case, O read as 0 and I or L as 1; six digits are read with white space around them only (as `trim` takes it).

## Depends on
- `kernel`, `mail`, `mfa-extensions` (the kind's contract), `mfa` (composed for it: it stays among this package's dependencies, so adding this kind composes `mfa`), `mfa-binding-proof` (its binding proofs, read to check `account-email` is composed; composed for it, as the proof's host), `users` (claimed contacts), `subject-attributes` (a session's vouched login attributes)
