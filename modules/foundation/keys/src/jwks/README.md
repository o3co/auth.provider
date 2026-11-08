# jwks

Internal module of `keys`: the public key set (JWKS) route.

## Responsibilities
- Answers the ring's unexpired public keys as a JWK set, with their public members alone.

## Not here
- Reading or rotating the keys (`signing`).

## Offers
- `jwksResponse` (the ring, the time, the request, how long it is cached) → the answer.
- `jwksSettings`: the section's `jwks-cache` part, which the package composes beside the ring's keys.

## Invariants
- The answer carries a strong ETag and answers 304 to it, cached as long as it is given; with nothing to publish it answers 404 `no-store`.

## Depends on
- None (`keys`' contract)
