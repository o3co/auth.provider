# client-secret

Internal module of `idp-apple`: the client's secret Apple asks for, signed by the team's key.

## Responsibilities
- Signs the secret as a short JWT, and holds it until half its life is spent.

## Not here
- Reading and checking the key at boot, and choosing a signed or a fixed secret (the package).

## Offers
- `secretOf` (team, key id, client, key, lifetime, audience; a clock) → `current()`, the secret to send now.

## Invariants
- The JWT's header is ES256 with the key id. It names the team as `iss`, the client as `sub` and Apple as `aud`, with `iat` and `exp` from the clock given.
- A held secret is made again once half its lifetime has passed. Requests at once share one signing; a signing that failed is not held.
- A held secret is tied to the key that made it: under another key, a new one is signed.

## Depends on
- `jose`
