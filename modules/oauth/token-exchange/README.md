# token-exchange

## Responsibilities
- Contributes the Token Exchange grant (RFC 8693), `urn:ietf:params:oauth:grant-type:token-exchange`. It issues access tokens only.
- Owns the extension point for the verifiers of the tokens a client may exchange. Verifies this provider's own access tokens itself.
- Builds the actor chain (`act`), and checks its depth and `may_act`.

## Not here
- Verifying other token types (the contributing side). Families and revocation (`refresh`, `tokens`). The link from a token to its session (`session-tokens`). Whether a binding carries over (`sender-binding`). Client authentication (`token-endpoint`). The client's allowance (`client-allowance`).

## Offers
- Composition definition. The grant, and the verifier of the type `urn:ietf:params:oauth:token-type:access_token` (through `tokens`).
- Extension point `token-exchange.verifiers`, one verifier per token type; a second for one type refuses the boot.
  - A verifier answers invalid, or a token by its `kind`, with its subject, issuer and expiry: `own`, naming the client by issued-to or audience, with its scope, audience, binding, actor chain and `may_act`; or `foreign`, another issuer's for an app, with `clients` (at least one) and `holderDigest`, `BASE64URL(SHA-256(jkt))` of the key a public client must hold. It throws unavailable when it cannot tell.
  - `issued` names a token this provider issued, so its family and session are found. Only the built-in verifier's `issued`, amr, authentication time and acr are read.
  - `consume(token)`, optional: records a once-only token, answering `consumed` or `replayed`.
- Client metadata section `token-exchange`: `others-tokens` (default false), whether the client may present tokens that do not name it; `public-exchange` (default false), whether a public client may exchange.
- Operator section: `max-actor-depth` (1–10, default 3); `max-lifetime` (1s–1d, optional, written with its unit), the longest lifetime an exchange may ask for, even past `tokens`' lifetime.

## Invariants
- Only a client explicitly allowed the grant: a confidential one, or a public one with `public-exchange`. Any other public client is `401 invalid_client`.
- A public client exchanges only a foreign subject token with a `holderDigest`, proving by DPoP the key it names; it is then issued a DPoP-bound token. A confidential client's `holderDigest` is unread.
- Refusals take the form and status of every grant's: `400`, or `401` for the client. A refused token or request is `invalid_request`.
- The subject token and the actor token must name the calling client, by issued-to or audience, unless its `others-tokens` is true. A foreign token must list the caller in `clients` instead, whatever `others-tokens` says.
- A once-only token (its verifier has `consume`), or a foreign one, is refused as the actor.
- The scope lies within the subject token's scope and the client's allowance; left out, it is the subject token's, cut to the client's. Wider is `invalid_scope`. For a foreign token, there is no scope or audience of its own: the client's allowance decides them, by the same rules for `audience` and `resource`.
- The audience is one the subject token holds and the client is allowed; left out, the only such one. A `resource` must be that audience. Otherwise `invalid_target`. It declares it takes its audience from the request, so no rule refuses its `resource` before it runs.
- Bindings follow `sender-binding`'s answer. A token bound to a key is never exchanged for one without it, for the subject and the actor alike.
- `act` is the actor's subject over the subject token's chain. Without an actor there is no `act`. A chain past `max-actor-depth` is refused. A `may_act` must name the actor, or the client when there is none; a client never matches an entry with an issuer.
- A revoked or expired token, one of an ended family, or one of a session that does not enter at use (closed, or short of a requirement, each told apart in the description) is refused, as subject or actor.
- The issued token joins the subject token's family, and is issued from the subject token's session when it has one, so `token-endpoint` has it recorded there; a session closed or short after that revokes it, and the exchange is refused.
- It never outlives the subject token or its family. Revoking the subject token alone does not end it.
- Its lifetime is the `expires_in` asked, or `tokens`' lifetime when none is asked, cut to `max-lifetime`; without that cap, `tokens`' lifetime cuts an asked one too. `expires_in` in the answer is that lifetime.
- `expires_in` left out or empty asks for nothing. Otherwise it is 1–10 ASCII digits above zero, or `invalid_request` before any token is checked.
- The subject's amr, authentication time and acr are carried only from this provider's own tokens.
- It issues through `tokens`' issuance policies, from the subject token's session when it was recorded to one; their refusal is `token-endpoint`'s answer.
- A verifier's answer is checked for shape once (each scope one RFC 6749 scope-token) and frozen; only that copy is read. An answer marked invalid, or a malformed one, is a failed validation, never a skipped family or session check.
- Both tokens, their family and their session are checked again right before issuing. A once-only token is then used up, once the policies admit the grant: a refusal or Unavailable leaves it unused, and `replayed` is refused.
- `requested_token_type` other than an access token is refused. Unavailable is `503`, never a refusal.

## Depends on
- `kernel`, `grants`, `client-allowance`, `tokens`, `clients`, `issuer`, `refresh`, `sender-binding`, `session-tokens`, `session`

## Vocabulary
- subject token: the token presented for exchange. actor token: the token of whoever acts for the subject.
- actor chain: who acts for the subject, and who they act for in turn.
