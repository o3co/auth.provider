# routes

Internal module of `federation-tokens`: the token and logout routes clients call.

## Responsibilities
- Answers a client's call for its session's upstream token, or for an upstream logout, under `/oauth/federation`.
- Declares the client metadata section that makes a client a receiver.

## Not here
- What each route answers and when (the package's card). Accepting the caller (`caller`). Keeping and renewing the tokens (`renewal`).

## Offers
- `routesIn` (the build context, the keeper) → the route, taking the caller check, `clients`, `upstreams`, `audit`, the erasure fence and the requests policy itself.
- `federationTokens` (the flow, a request) → the answer; `clientSection`; `base`.

## Invariants
- Both routes answer `no-store` and are limited per source by `rate-limit`'s requests policy.
- A token is answered only past the erasure fence, after the session's check again: one fenced write per answer where erasure is enabled, under a receipt of 128 fresh random bits; with it off, the fence passes writing nothing. `erased` is answered `401 invalid_token`, as a session that no longer enters, and recorded as nothing; a fence that cannot answer is `503`.
- Where erasure is enabled, a token is answered only where its fence's receipt committed before the subject's erasure mark. A request past the fence may still answer after the mark, even after the erasure is done (promise 4). An upstream token handed out lives at the upstream until its end.

## Depends on
- `audit`, `clients`, `http`, `kernel`, `rate-limit`, `redirect-uris`, `request-source`, `subject-revocation` (the erasure fence), `upstreams`; `caller`, `renewal`, the package's end of session, section and audit events
