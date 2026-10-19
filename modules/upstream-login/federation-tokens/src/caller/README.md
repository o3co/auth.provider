# caller

Internal module of `federation-tokens`: accepting the access token a request presents.

## Responsibilities
- Accepts a presented access token and names its client, its session and its subject.

## Not here
- Whether the client receives upstream tokens (the package). What the routes answer (the package).

## Offers
- `callerWith` (sender-binding, tokens, session-tokens, sessions) and `callerFrom` (the composition): `accepted` (request → accepted / refused with status, error and headers), `stillEnters` (accepted → whether its session still enters at `use` for its subject)

## Invariants
- Admission is `sender-binding`'s, with `tokens`' check. Past it, every refusal is `401 invalid_token` in the token's scheme.
- Checked in order: `sender-binding` admits the token through `tokens`, every access condition holding (its family's among them); the audience names the client; the token was issued in a session; that session enters at `use` for the token's subject (one short of a requirement does not).
- A check that cannot tell throws Unavailable.

## Depends on
- `http`, `kernel`, `tokens`, `sender-binding`, `session-tokens`, `session`
