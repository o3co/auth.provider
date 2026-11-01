# federation-grants

## Responsibilities
- Takes a confidential client's intent to act for a user at one connection, and owns its steps through the browser and upstream, which a browser half runs over `grantIntents`.
- Holds the upstream credentials apart from any session, and hands the client the upstream's bearer token, refreshed under a lock within a rotation budget.
- Seals again, for `seal`'s resealers (as `federation-grants`), credentials a `previous` key sealed: walking every grant, writing only over the credentials read and keeping the grant's lifetime, counting those no key opens. A refresh seals under the current key anyway.
- Answers a grant's status, renewal and revocation, and follows a subject's revocation.
- Internal modules: `grant` (records, sealing, shared judgments), `api` (client routes and the follower), `sweep` (erasing credentials no request reads), `intents` (an intent's steps, for the browser half), `refresh` (tokens, for `api`).

## Not here
- The browser half, whose upstream account a callback reached, and the browser settings (`federation-grants-connect`). The upstream's requests (`upstreams`' IdP type), revocation boundaries (`subject-revocation`), consent to this provider's clients (`consent`).

## Offers
- Client routes, for an operator's confidential client (else `401 invalid_client`), JSON or form:
  - `POST /oauth/federation-grants` (`connection`, `sub`, `redirect_uri`, `state`, `scope?`, `expires_in?`, `upstream_sub?`): `201` with `grant_id`, `status`, `connect_uri`, `connect_expires_in`, `expires_in`.
  - `POST …/<id>/reauthorize` (the same, `connection` optional): `201` alike.
  - `POST …/<id>/token` (`sub`, `scope?`, `min_ttl?`, `connection?`, `resource?`): `200` with `access_token`, `token_type`, `expires_in`, `scope`.
  - `POST …/<id>/status` (`sub`): `200`, with `last_used_at` once a token was handed, to a client still allowed the connection. `…/<id>/revoke` (`sub`): `204`.
  - Errors: `grant_not_found` (404), `authorization_pending`, `invalid_request`, `invalid_scope`, `invalid_target` (400), `access_denied` (403), `grant_revoked`, `grant_expired`, `reauthorization_required` (410), `rate_limited` (429), `upstream_token_ineligible`, `upstream_rejected` (502, `retry-after: 300`), `temporarily_unavailable` (503).
- Browser routes: `GET …/session/federation-grants/connect?request=`, `GET` and `POST …/consent` (`challenge`, `decision`; the POST under `csrf`), `GET …/callback/<connection>`, which returns to the intent's URI with `grant_id`, `state` and any `error`; answered by the one browser half at `grantsBrowsers`. Their connect path is a `login-gates` return path, so a browser sent to log in or raise its session comes back to it.
- The client routes and the connect and callback `GET`s take other sites' requests, each with its reason declared (a client's own authenticated call, the client's navigation, the upstream's redirect); the consent's `POST` is checked by `csrf` before its source is counted.
- `grantIntents`: the browser half's intent steps on an opaque `IntentRef`; `grantsBrowsers`: its route handlers, exactly one.
- Client metadata `federation-grants`: `connections`, `return-uris` (exact, each one `redirect-uris`' `registrable` takes, holding no `grant_id`, `state` or `error`).
- Operator section:
  - `connections.<name>` (`idp`, `scopes` with `openid`, `resource?` an absolute URI with no fragment or query, `max-access-token-lifetime`, `scope-subsets`)
  - `default-lifetime`, `max-lifetime` (`30d`)
  - `connect-lifetime` (`10m`)
  - `refresh-before` (`30s`)
  - `rotations` per `rotation-window` (24 per `1h`)
  - `lodges` per `lodge-window` (60 per `1m`), lodgings and renewals together
  - `keep-on-subject-revocation` (false)
  - `sweep-interval` (`1h`): how often each host walks every grant kept, erasing the credentials of one ended or revoked that no request reads
  - `requests` per `window`
  - Times are written with their unit; a bare number is refused.
- Follower of `subject-revocation`: writes at once, for each grant listed under the subject, what the boundary decides at the next read.
- Store interfaces the assembly wires: grants by id, walked by pages (no eviction, durable, replicated, confirmed reads); steps by secret (no eviction, replicated, names from the secret); pending first-time intents per client and subject, and each subject's grants (keyed sets; the listing also durable and replicated); and the refresh lock store (no eviction), each lock held under its holder's mark and changed only over the mark read, so a holder lets go of its own lock and never another's.
- Audit events `federation.grant.*`: `requested`, `request.denied`, `authorized`, `reauthorized`, `authorization_failed`, `token.success`, `token.denied`, `revoke.denied`, `revoked`, with `client`, `connection` and an outcome or reason, `unavailable` where the store could not answer.
- `./testing`: configuration builders and the store interfaces' contract tests, one for the refresh lock store.

## Invariants
- A grant route reads the body, then the owner; an unknown grant and another client's or subject's answer the same bytes.
- Only a bearer token with a refresh token, a finite life within the connection's and a scope within what was shown is held.
- A revocation is the end: no refresh or activation writes over it, and an ordinary logout leaves grants.
- A subject's boundary ends a grant when read, in whole seconds with nothing allowed for hosts' clocks; with `keep-on-subject-revocation`, only `delegations` does, which every start warns of (`federation-grants.kept_on_subject_revocation`).
- A failed listing is logged and passed: the boundary still refuses what the follower misses.
- Credentials are sealed to the grant's id, subject, client and connection, and erased once revoked, sent to reauthorization, or read past the end.
- Tokens, secrets and upstream text reach neither answers, logs nor audit.

## Depends on
- `kernel`, `http`, `request-source`, `clients`, `csrf`, `upstreams`, `seal`, `subject-revocation`, `rate-limit`, `audit`, `login-gates`, `redirect-uris` (`registrable`, the rule for return URIs)

## Vocabulary
- intent: a client's asking for a grant, connected once by the user. connection: an entry of the operator's `connections`, and the user's steps for an intent.
- grant: the credentials held for a client and subject at a connection, with its state.
