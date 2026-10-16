# caller

Internal module of `federation-tokens`: accepting the access token a request presents.

## Responsibilities
- Accepts a presented access token and names its client, its session and its subject.

## Not here
- Whether the client receives upstream tokens (the package). What the routes answer (the package).

## Offers
- `callerWith` (sender-binding, tokens, lineage, session-tokens, sessions) and `callerFrom` (the composition): `accepted` (request → accepted / refused with status, error and headers), `stillOpen` (accepted → whether its session is still open for its subject)

## Invariants
- Admission is `sender-binding`'s, with `tokens`' check. Past it, every refusal is `401 invalid_token` in the token's scheme.
- Checked in order: the audience names the client, the family has not ended, the token was issued in a session, that session is open for the token's subject.
- A check that cannot tell throws Unavailable.

## Depends on
- `http`, `kernel`, `tokens`, `sender-binding`, `refresh`, `session-tokens`, `session`
