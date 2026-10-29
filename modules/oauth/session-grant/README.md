# session-grant

## Responsibilities
- Contributes the grant `session`: a client beside the user's browser (first-party, or a backend for its frontend) gets an access token for the user of the browser's session.
- Issues each token from that session, so `token-endpoint` has it recorded there and closing the session ends it.

## Not here
- Entering the session and its requirements (`session`). Whether a request shows same-origin evidence (`csrf`).
- Client authentication, and recording the tokens issued from a session (`token-endpoint` and what contributes to its session issuances). The grant's allowance, scope and audience (`client-allowance`).
- Refresh tokens and ID tokens: it issues neither.

## Offers
- Composition definition only (the grant). A client may use it once its `client-allowance` section lists `session`; a public client too.
- Answers `200` with `access_token`, `token_type`, `expires_in`, and `scope` when one is issued.
- Refusals:
  - No same-origin evidence, or no session to enter: `400 invalid_grant` (RFC 6749 §5.2), described as not authenticated.
  - A session short of an entry requirement: `invalid_grant`, with `step_up` naming the requirement.
  - A scope outside the client's allowance, or none asked where the client has no defaults: `invalid_scope`.
  - An issuance policy's refusal: `invalid_grant`, with the policy's description.
  - A session that can no longer be entered once its token is recorded: `invalid_grant`.

## Invariants
- A request without same-origin evidence is refused before the session is read; the cookie alone never issues. The grant declares `readsAmbient: cookie`, as `grants` asks of one reading the session's cookie.
- Only the authenticated client counts. A `client_id` in the body is never read.
- The scope and audience are `client-allowance`'s allowed issuance for the client; a scope left out is the client's defaults.
- The subject, amr and authentication time (or that it is not known) are those of the session entered at level `use`; the token never outlives that session.
- It issues through `tokens`' issuance policies from that session; a refusal records nothing and is `token-endpoint`'s answer.
- A token is recorded to its session in issuing, before it is answered; if recording fails, it is revoked, as `token-endpoint` issues it. If the session can no longer be entered once it is recorded, or cannot tell, the token is revoked.
- The request's binding is carried into the token, as `token-endpoint` issues it.
- When it cannot tell, the failure passes on as unavailable, never as a refusal.
- Boot is refused where nothing contributes to `grants`' session issuances: its tokens must be recorded to their session, so that a logout ends them.

## Depends on
- `kernel`, `grants`, `client-allowance`, `tokens`, `session`, `csrf`, `issuer`
