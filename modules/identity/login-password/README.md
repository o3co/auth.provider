# login-password

## Responsibilities
- Provides the password login endpoint: verifies with `users`, and logs in through `login-gates`, reporting the time the password was verified as the login's authentication time.

## Not here
- Steps after verification, such as a second factor: `login-gates` and its gates.
- Where a login may return: `login-gates`.
- The login screen: the deployer's.

## Offers
- Contribution to `login-gates`: the amr a password login proves, `pwd`.
- Route `POST /session/login`, taking a form or JSON with `username`, `password` and `redirect_to`.
- Success is `200` with `{}` or `{redirect_to}`; a gate holding the login is `403` with the gate's answer and cookies, unread.
- Errors: `csrf` (403), `repeated_parameter`, `invalid_redirect`, `invalid_request` (400), `too_many_attempts` (429), `service_unavailable` (503, attempts uncounted), `invalid_credentials` (401), `temporarily_unavailable` (503).
- Audit events to `audit`, with `method` `password` and the `source` where `request-source` determined it: declared in `./audit-events`, listed in the audit event reference.
- Operator section: `attempts` per source (1–100, default 20) in `window` (1m–1d, default `15m`). Times are written with their unit; a bare number is refused.
- Operator section, per identifier: `account-attempts` (1–100, default 10), `account-window` (1m–1d, default `1h`, no shorter than the longest wait), `account-max-wait` (1s–1h, default `5m`).

## Invariants
- Checks run in this order: `csrf`, attempts per source, the body's type, repeated parameters, destination, credentials present, attempts per identifier, credentials matching.
- `http` reads the body, then applies both policies, CSRF first (its token may come in the body), before the handler judges the request, so a malformed request counts as an attempt.
- Every attempt is counted, whoever the user and whatever the outcome; how a source is keyed is `rate-limit`'s.
- Attempts are also counted per identifier tried, from any source, by its NFKC lowercase form, hashed: counted and answered alike whether an account has it.
- Past `account-attempts` failures in a run, each next attempt at the identifier waits, `429` `too_many_attempts` with `retry-after`, and its password is not checked.
- An identifier's wait doubles from a second to `account-max-wait`, and never locks it out.
- Anyone who knows an identifier can keep its password login waiting, up to `account-max-wait` at a time, for as long as they keep trying; passkey and federation logins are not held back.
- The right password ends the identifier's run; a guess `users` could not judge is handed back.
- An identifier's run is forgotten after `account-window` without a failure.
- Where the attempt per identifier cannot be counted, the login is `503` `service_unavailable`.
- The password is handed to `users` as typed, with no Unicode normalization.
- A JSON `redirect_to` that is neither a string nor null is `invalid_redirect`; any other member that is no string counts as absent.
- A destination is taken only where `login-gates` says a login may return, and refused before the credentials are looked at.
- With both credentials present, a failure tells neither whether the user exists nor what was wrong.
- A `503` after matching, and a gate's `403`, come only with a correct password; counting attempts per source and per identifier holds that down.
- The success answer is handed to the gates as the continuation, returned once they let the login through.
- The login gives the session the user's attributes from `users`' answer, under `login-attributes`' source name for users (`loginSource.users`): `email`, `email_verified` (a boolean only), `name`, `picture` and `groups` (strings only), read by these names; any other is left out. `session` applies the caps.
- Answers are never cached.
- An audit event carries the subject only when the password matched, and never the username, the password or why a login failed.
- Nothing is recorded for a request refused before the credentials are matched, or for one answered unavailable.

## Data
- None of its own: the attempts per source and per identifier (a hash, never the identifier) are `rate-limit`'s.

## Depends on
- `kernel`, `http`, `request-source`, `users`, `login-attributes` (the source name), `login-gates`, `csrf`, `rate-limit`, `audit`

## Vocabulary
- destination: where to return after login.

## Rules for callers
- The login screen moves to the answer's `redirect_to`, not to the value it sent.
