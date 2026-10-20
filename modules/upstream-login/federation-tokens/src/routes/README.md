# routes

Internal module of `federation-tokens`: the token and logout routes clients call.

## Responsibilities
- Answers a client's call for its session's upstream token, or for an upstream logout, under `/oauth/federation`.
- Declares the client metadata section that makes a client a receiver.

## Not here
- What each route answers and when (the package's card). Accepting the caller (`caller`). Keeping and renewing the tokens (`renewal`).

## Offers
- `routesIn` (the build context, the keeper) → the route, taking the caller check, `clients`, `upstreams`, `audit` and the requests policy itself.
- `federationTokens` (the flow, a request) → the answer; `clientSection`; `base`.

## Depends on
- `audit`, `clients`, `http`, `kernel`, `rate-limit`, `request-source`, `upstreams`; `caller`, `renewal`, the package's end of session, section and audit events
