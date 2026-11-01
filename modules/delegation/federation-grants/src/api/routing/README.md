# routing

Internal module of `api`: the routes a grant answers by id.

## Responsibilities
- Reads a route's body, then the grant's owner, then, where the route judges it, the subject's boundary and the grant's end, before the route answers.

## Not here
- What each route answers: `lodging`, `tokening`, `revoking`.

## Offers
- `routingWith` (the api's common parts, the routes) → `byId`.

## Invariants
- A grant another client or subject holds is answered as an unknown one, byte for byte.
- A grant the boundary covers is written revoked before anything else; one past its end loses its credentials under a new version.
- An outage is audited as the route's refusal, recording best effort.

## Depends on
- `clients`, `http`, `kernel`; `grant`, `body.ts`, the api's common parts.
