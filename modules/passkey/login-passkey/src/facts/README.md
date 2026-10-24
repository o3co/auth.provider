# facts

Internal module of `login-passkey`: the login's facts for what an assertion proved.

## Responsibilities
- Reads the subject's user and makes the facts a session opens with.

## Not here
- When the facts are asked (`opening`).

## Offers
- `factsIn` → a function (what the assertion proved) → the facts, or `users`' none or unanswerable; `amrOf` (whether the user was verified, `counts-as-mfa`) → the amr.

## Invariants
- The amr is `pop`, and `mfa-extensions`' second factor (`mfa`) only where the user was verified and `counts-as-mfa` is on; whether the passkey is backed up changes nothing.
- The authentication time is the challenge's time, on `kernel`'s clock.
- The attributes are those `users` accepts, under `login-attributes`' source name for users.

## Depends on
- `users`, `login-attributes`, `mfa-extensions`
