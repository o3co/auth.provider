# oidc

## Responsibilities
- Makes the ID token (a contribution to `code-grant`'s ID token makers, for the `openid` scope).
- Holds the fixed claim table (which claims each scope releases) and maps a user's attributes through it (`src/claims/`).
- Answers the claims released for a subject and scope; userinfo reads claims only through this.

## Not here
- Judging the authentication context and its level (the caller passes them). Signing (`keys`). When to issue an ID token (`code-grant`).
- What a user's attributes hold and where they come from (`users`, `session`), and which source counts (`subject-attributes`). Accepting a token for userinfo (`userinfo`).

## Offers
- `releasedClaims.of` (subject, scope words, optionally the session's handle → the released claims; never `sub`)
- `idTokenHints.check` (an ID token given back as a hint → its subject, session, client and issue time / sessionless / invalid)
- A contribution to `code-grant`'s ID token makers
- `issuer`'s metadata items: `scopes_supported` (`openid` and the table's scopes), `claims_supported` (`sub` and the table's claims), `subject_types_supported` (`public` only), `id_token_signing_alg_values_supported` (the algorithm `keys` signs with)
- Operator section: `id-token-lifetime` (a duration written with a unit, `1m`–`1d` in whole seconds; default `1h`)

## Invariants
- Only the table's claims are released; an attribute outside it, a value of another type, or a nested object never is.
- From `groups`, elements that are not strings are dropped.
- A scope word counts only when it is exactly a table scope.
- Scope words joined by a tab or another blank release nothing.
- Attributes are read on each request through `subject-attributes`, from any source it answers with: `users`, or else the session's login. `email_verified` is released only from what `subject-attributes` answers as vouched for by `users`, never from an upstream's login. When neither can say, or the subject has no user, no claims are released; a `users` or `session` failure is unavailable, never an empty answer.
- Refuses at boot unless the `keys` signer uses an asymmetric key (with a shared secret, any RP that knows it could forge tokens).
- The ID token's `typ` is the standard `JWT`. Telling token kinds apart is the receiver's check of its own kind, not this spelling.
- A hint is taken only as an ID token `keys` verifies under `JWT`, from `issuer`'s URL, with a subject, `iat` and `exp`, whatever its `exp` (OpenID Connect RP-Initiated Logout 1.0 §2: an expired hint is still taken); its audience is not pinned. Its client is `azp` when the audience names it, else the one audience.
- `auth_time` never exceeds `iat` (so clock skew cannot put it later).
- An unknown authentication time is never claimed: the ID token then carries no `auth_time`.
- The ID token carries `iss` (`issuer`'s URL), `sub`, `aud` and `azp` (the client), `iat`, `exp`, `auth_time` (when the authentication time is known), `amr`, `sid` (the session's handle); `nonce` only when the request had one, `acr` only when the code had one; and the claims released for the code's scope and session, which never stand for any of these.

## Claim table
| scope | claim | attribute | type |
|---|---|---|---|
| `profile` | `name`, `picture` | the same name | string |
| `email` | `email` | `email` | string |
| `email` | `email_verified` | `email_verified` | boolean |
| `groups` | `groups` | `groups` | list of strings |

## Depends on
- `kernel`, `keys`, `issuer`, `code-grant`, `users` (the attribute names), `subject-attributes`

## Vocabulary
- claim table: the fixed rows of scope, claim, attribute and type.
- released claims: a subject's attributes mapped through the table for the scopes asked.
