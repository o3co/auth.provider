# subject-attributes

## Responsibilities
- Answers a subject's attributes from one source, bridging `users` and `session`, and whether `users` vouches for them: the one place for the rule of which source counts.
- A module of its own so that every caller (`oidc`, `verified-email`) reads the same rule: `users` when it answers, else the session's login, never mixed. Keeping it out of `oidc` also keeps `oidc` from depending on `session`.

## Not here
- The attributes and their names (`users`). A login's attributes and their checks (`login-attributes`). What a caller does with attributes nobody vouches for (each caller decides).

## Offers
- `subjectAttributes.of` (subject, optional session handle → known with its source, attributes and `vouched` when `users` vouches for them / unknown).
- `vouches` (a login's sourced attributes → whether `users` vouches for them), the same rule for a login not yet in a session.

## Invariants
- When `users` answers for the subject, the answer is its attributes under the source `users`, and the session is not read; a subject with no user has none.
- Only when `users` cannot look the subject up, the answer is the login attributes of the session the handle names, under the source `session:<the login's source>`, if it is open and the subject's.
- Vouched only when `users` states the attributes: its own answer (a subject with no user too), or a login kept under `login-attributes`' source name for users (`loginSource.users`). An upstream's login never is.
- Sources are never mixed; with no such session or no attributes in it, the answer is unknown, never empty.
- A `users` or `session` failure is unavailable.
- Attributes are by `users`' names (`userAttribute`), each value as its source holds it; no list of names is kept here.

## Depends on
- `kernel`, `users`, `session`, `login-attributes`
