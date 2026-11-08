# account-mail-code

## Responsibilities
- Mails a code to the account's address, as `users` states or vouches for it, and checks a typed code against it, for the second-factor kinds and proofs that name the purpose.

## Not here
- The purpose a code is mailed under, its wording, and what the code proves (the caller's). Delivering mail and its limits (`mail` and its sender). The account's addresses (`users`). Keeping a code between its send and its check (the caller's, sealed where it keeps secrets).

## Offers
- `mailedCodes` (mail, users, a session's attributes, the clock) → `addressNow` (subject, where asked from → the address, as the invariants below choose it), `send` (the caller's purpose, address, code, end → sent with what to show and keep / limited) and `matches` (kept code, typed → whether it is the code, before its end).
- `mailedCodesIn` (the build context): the same, taking them from the assembly; a module calling it names `mailedTakes` in its takes.
- `longCode` (16 characters of Crockford's base32, 80 bits) and `readLongCode`; `shortCode` (six digits) and `readShortCode`.
- A sent code shows `{sent_to, expires_in}`: the address's first character and its domain, and the seconds the code lives; the mail takes `code` and `minutes`.

## Invariants
- The address is the account's claimed `email` contact in `users`, in NFC and `mail-address`'s canonical form (its domain in ASCII, lower case), so one mailbox has one form; none, one `mail-address` does not take, or a `users` that cannot tell gives none.
- Without one, it is the `email` the login gave when `users` vouches for it (an outside ledger's answer): a held login's as `mfa` passes it on, `vouched`, or the session's by `subject-attributes`. An upstream's claim is never read.
- A code is compared in constant time, and refused past its end. A sender's limit is `limited`; a sender that cannot tell passes on as unavailable.
- A long code is read from ASCII letters, digits, hyphens and spaces only, in any case, O read as 0 and I or L as 1; six digits are read with white space around them only (as `trim` takes it), each drawn as likely as any other.

## Depends on
- `kernel`, `mail`, `mail-address` (the address's one form), `mfa-extensions` (where a code is asked from, and what a send answers), `users` (claimed contacts), `subject-attributes` (a session's vouched login attributes)
