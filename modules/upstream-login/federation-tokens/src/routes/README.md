# routes

Internal module of `federation-tokens`: the token and logout routes clients call.

## Responsibilities
- Answers a client's call for its session's upstream token, or for an upstream logout, under `/oauth/federation`.
- Declares the client metadata section that makes a client a receiver.

## Not here
- What each route answers and when (the package's card). Accepting the caller (`caller`). Keeping and renewing the tokens (`renewal`).

## Offers
- `routesIn` (the build context, the keeper) → the route, taking the caller check, `clients`, `upstreams`, `audit`, the erasure fence and the requests policy itself.

## Invariants
- Both routes answer `no-store` and are limited per source by `rate-limit`'s requests policy.
- A token is answered only past the erasure fence, after the session's check again: one fenced write per answer, under a receipt of 128 fresh random bits; `erased` is answered `401 invalid_token`, as a session that no longer enters, and recorded as nothing; a fence that cannot answer is `503`.
- `federationTokens` (the flow, a request) → the answer; `clientSection`; `base`.

## Depends on
- `audit`, `clients`, `http`, `kernel`, `rate-limit`, `redirect-uris`, `request-source`, `subject-revocation` (the erasure fence), `upstreams`; `caller`, `renewal`, the package's end of session, section and audit events
