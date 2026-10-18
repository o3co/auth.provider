# federation-grants

## Responsibilities
- Takes a confidential client's intent to act for a user at one connection, and walks the user through it in the browser and upstream.
- Holds the upstream credentials apart from any session, and hands the client the upstream's bearer token, refreshed under a lock within a rotation budget.
- Seals again, for `seal`'s resealers (as `federation-grants`), credentials a `previous` key sealed: walking every grant, writing only over the credentials read and keeping the grant's lifetime, counting those no key opens. A refresh seals under the current key anyway.
- Answers a grant's status, renewal and revocation, and follows a subject's revocation.
- Internal modules: `grant` (records, sealing, shared judgments), `api` (client routes and the follower), `sweep` (erasing credentials no request reads), `connect` (browser half), `refresh` (tokens, for `api`). Each takes the contracts it uses from the build context; the package's module only declares the routes and contributions they fill, and starts the sweep with the shared parts.

## Not here
- The upstream's requests (`upstreams`' IdP type), who holds an upstream account (`users`), revocation boundaries (`subject-revocation`), session entry (`session`), consent to this provider's clients (`consent`).

## Offers
- Client routes, for an operator's confidential client (else `401 invalid_client`), JSON or form:
  - `POST /oauth/federation-grants` (`connection`, `sub`, `redirect_uri`, `state`, `scope?`, `expires_in?`, `upstream_sub?`): `201` with `grant_id`, `status`, `connect_uri`, `connect_expires_in`, `expires_in`.
  - `POST …/<id>/reauthorize` (the same, `connection` optional): `201` alike.
  - `POST …/<id>/token` (`sub`, `scope?`, `min_ttl?`, `connection?`, `resource?`): `200` with `access_token`, `token_type`, `expires_in`, `scope`.
  - `POST …/<id>/status` (`sub`): `200`, with `last_used_at` once a token was handed, to a client still allowed the connection. `…/<id>/revoke` (`sub`): `204`.
  - Errors: `grant_not_found` (404), `authorization_pending`, `invalid_request`, `invalid_scope`, `invalid_target` (400), `access_denied` (403), `grant_revoked`, `grant_expired`, `reauthorization_required` (410), `rate_limited` (429), `upstream_token_ineligible`, `upstream_rejected` (502, `retry-after: 300`), `temporarily_unavailable` (503).
- Browser routes: `GET …/session/federation-grants/connect?request=`, `GET` and `POST …/consent` (`challenge`, `decision`; the POST under `csrf`), `GET …/callback/<connection>`, which returns to the intent's URI with `grant_id`, `state` and any `error`.
- Client metadata `federation-grants`: `connections`, `return-uris` (exact, holding no `grant_id`, `state` or `error`).
- Operator section:
  - `page`, `login-page`, `step-up-page` (https; http only on a loopback host)
  - `connections.<name>` (`idp`, `scopes` with `openid`, `resource?`, `max-access-token-lifetime`, `scope-subsets`)
  - `default-lifetime`, `max-lifetime` (`30d`)
  - `connect-lifetime` (`10m`)
  - `refresh-before` (`30s`)
  - `rotations` per `rotation-window` (24 per `1h`)
  - `lodges` per `lodge-window` (60 per `1m`)
  - `keep-on-subject-revocation` (false)
  - `revocation-skew` (`1s`)
  - `sweep-interval` (`1h`): how often each host walks every grant kept, erasing the credentials of one ended or revoked that no request reads
  - `identity-check` (`required`)
  - `requests` per `window`
  - Times are written with their unit; a bare number is refused.
- Follower of `subject-revocation`: writes at once, for each grant listed under the subject, what the boundary decides at the next read.
- Store interfaces the assembly wires: grants by id, walked by pages (no eviction, durable, replicated, confirmed reads); steps by secret (no eviction, replicated, names from the secret); pending first-time intents per client and subject, and each subject's grants (keyed sets; the listing also durable and replicated); and the refresh lock store (no eviction), each lock held under its holder's mark and changed only over the mark read, so a holder lets go of its own lock and never another's.
- Audit events `federation.grant.*`: `requested`, `request.denied`, `authorized`, `reauthorized`, `authorization_failed`, `token.success`, `token.denied`, `revoke.denied`, `revoked`, with `client`, `connection` and an outcome or reason.
- `./testing`: configuration builders and the store interfaces' contract tests, one for the refresh lock store.

## Invariants
- A grant route reads the body, then the owner; an unknown grant and another client's or subject's answer the same bytes.
- A state is spent before its code is exchanged, at its own connection; the intent, browser session and subject are checked before and after the exchange.
- The upstream account matches the grant's and the client's `upstream_sub`; with `identity-check: required`, another holder or no answer refuses.
- Only a bearer token with a refresh token, a finite life within the connection's and a scope within what was shown is held.
- A revocation is the end: no refresh or activation writes over it, and an ordinary logout leaves grants.
- A subject's boundary, widened by `revocation-skew`, ends a grant when read; with `keep-on-subject-revocation`, only `delegations` does.
- A failed listing is logged and passed: the boundary still refuses what the follower misses.
- Credentials are sealed to the grant's id, subject, client and connection, and erased once revoked, sent to reauthorization, or read past the end.
- Tokens, secrets and upstream text reach neither answers, logs nor audit.

## Depends on
- `kernel`, `http`, `url-setting`, `request-source`, `clients`, `session`, `csrf`, `users`, `upstreams`, `seal`, `subject-revocation`, `rate-limit`, `audit`

## Vocabulary
- intent: a client's asking for a grant, connected once by the user. connection: an entry of the operator's `connections`, and the user's steps for an intent.
- grant: the credentials held for a client and subject at a connection, with its state.
