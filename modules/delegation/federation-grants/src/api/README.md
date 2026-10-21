# api

Internal module of `federation-grants`: the client routes, and the revocation follower.

## Responsibilities
- Lodges intents and renewals, and answers a grant's token, status and revocation.
- Follows a subject's revocation through the grants listed under it (`follow.ts`).

## Not here
- The browser half (`connect`), token renewal (`refresh`), record shapes (`grant`).

## Offers
- `apiOver` (the build context) → the handler of `/oauth/federation-grants/…`, through `apiWith` (clients, stores, attempt limit, `grant`'s parts, `refresh`, upstreams, audit, settings, origin, runtime).
- `bodyOf`: a route's body by the names it takes, as text or whole numbers.
- `followerOver` (the build context) → the follower, through `followerWith` (grants, listing, records, the judge once built, audit).

## Invariants
- A route reads the body, then the owner, then the grant's state and boundary, its end, the configuration, and only then the request's assertions.
- A grant the boundary covers is written revoked, without credentials, before anything else; a grant read past its end loses its credentials, under a new version, so a refresh that read it before writes nothing back.
- A refused client authentication is recorded through `clients`' `recordRefusedAuthentication`; a known public client is no such refusal.
- Every refused token request is audited once with a reason naming the refusal; before the owner is known, by the client only.
- A revocation is `204` in any state and audited once; a pending grant's status needs the client to still be allowed.
- Lodgings are counted per client before they are written; pushed-out intents end.
- The follower writes only over the state it judged, ends a covered grant or pending intent, and leaves an established grant kept with only its renewal ended.

## Depends on
- `http`, `request-source`, `clients`, `rate-limit`, `audit`, `upstreams` (the configured connections), `subject-revocation` (the follower's type), `kernel`; `grant`, `refresh`, the package's store interfaces
