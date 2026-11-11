# api

Internal module of `federation-grants`: the client routes, and the revocation follower.

## Responsibilities
- Lodges intents and renewals, and answers a grant's token, status and revocation, through its internal modules, each as its own card says: `lodging` (lodging and renewing), `tokening` (the token and the status), `revoking` (a client's revocation) and `routing` (a grant's routes by id).
- Follows a subject's revocation through the grants listed under it (`follow.ts`).

## Not here
- The browser half (`federation-grants-connect`, through `intents`), token renewal (`refresh`), record shapes (`grant`).

## Offers
- `apiOver` (the build context) → the handler of `/oauth/federation-grants/…`, through `apiWith` (clients, stores, attempt limit, `grant`'s parts, `refresh`, upstreams, audit, settings, origin, runtime).
- The errors the client routes answer: `grant_not_found` (404), `authorization_pending`, `invalid_request`, `invalid_scope`, `invalid_target` (400), `access_denied` (403), `grant_revoked`, `grant_expired`, `reauthorization_required` (410), `rate_limited` (429), `upstream_token_ineligible`, `upstream_rejected` (502, `retry-after: 300`), `temporarily_unavailable` (503).
- `bodyOf`: a route's body by the names it takes, as text or whole numbers.
- `followerOver` (the build context) → the follower, through `followerWith` (grants, listing, records, the judge once built, audit).

## Invariants
- A route reads the body, then the owner, then the grant's state and boundary, its end, the configuration, and only then the request's assertions.
- A grant the boundary covers is written revoked, without credentials, before anything else; a grant read past its end loses its credentials, under a new version, so a refresh that read it before writes nothing back.
- A refused client authentication is recorded through `clients`' `recordRefusedAuthentication`; a known public client is no such refusal.
- Every refused token request is audited once with a reason naming the refusal; before the owner is known, by the client only.
- A revocation is `204` in any state and audited once, written and unlisted by `retention`'s rules, as the backstop's is; a pending grant's status needs the client to still be allowed.
- Lodgings are counted per client before they are written; pushed-out intents end.
- The follower writes only over the state it judged, ends a covered grant or pending intent, and leaves an established grant kept with only its renewal ended.
- Told the subject is erased, it still ends the grants and drops their entries, and records each end (`federation.grant.revoked`) without the subject, `withheld` `erased`: `subject-revocation`'s rule for whoever is told it.

## Depends on
- `http`, `request-source`, `clients`, `rate-limit`, `audit`, `upstreams` (the configured connections), `subject-revocation` (the follower's type), `kernel`; `grant`, `retention`, `refresh`, the package's store interfaces
