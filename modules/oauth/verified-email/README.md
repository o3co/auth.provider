# verified-email

## Responsibilities
- Contributes the issuance policy `verified-email`: no access token for a subject whose email users has not stated verified.

## Not here
- Verifying an address, and the value that says so (`users`, its ledgers). Which source answers for a subject (`subject-attributes`).
- Where the policy is asked, and the answer to a refusal (`tokens`, `token-endpoint`, and the early refusals of `authorize` and `device-grant`).

## Offers
- Composition definition only (the policy). Composed only when the operator adds it; it has no section.
- Refusal: reason `email_not_verified`, description `email address is not verified`.

## Invariants
- Only `email_verified` exactly `true` counts as verified; absent, `false` or any other value is not.
- Only attributes `subject-attributes` answers as vouched for by `users` count. An upstream's word is never read as verified.
- Where users cannot look subjects up, it judges by the values the login brought; a change in the ledger after login shows only once that session closes.
- A subject no source answers for is refused.
- An issuance its issuer marks `continuing` (`tokens`' mark, set by a refresh) and `client_credentials` are let by unread; every other issuance, a later grant type's too, is judged.
- It only judges: it counts and writes nothing.
- When the attributes cannot be read, it is unavailable, never a refusal.

## Depends on
- `kernel`, `tokens`, `subject-attributes`, `users` (attribute names), `client-credentials` (the grant's name alone, a helper: composing this policy composes no grant)
