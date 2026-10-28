# faults

Internal module of `conformance-oauth`: what the area's fault scenes share in its words, its scene and the store writes a fault is about; the deployment, the waits and the repointing around a fault are `conformance`'s (`fault-scene`).

## Responsibilities
- Gives the JWT bearer grant's scene on the Redis store, one client trusting one issuer, and runs a scene on a deployment of its own on that scene unless it names another; client credentials' scene for a client authenticating by its key (`private_key_jwt`); and client credentials with DPoP, for a client binding its tokens to its holder's key.
- Signs an assertion of that issuer, or of that client to authenticate, or a DPoP proof of the holder's key, each with a `jti` of its own, and sends it to an instance's token endpoint.
- Names an assertion's spend as the relay matches it: its record placed under the issuer's and the `jti`'s name in `jwt-bearer-store.spent`, under the client's and the `jti`'s in `client-assertion-store.spent`, or a proof's under its key's thumbprint and its `jti` in `dpop-store.spent`.

## Offers
- `faultScene`, `keyedScene`, `dpopScene`, `on` (`conformance`'s, on `faultScene` by default), `assertion`, `clientAssertion`, `proof`, `grantAt`, `authenticatedAt`, `provenAt`, `said`, `spendOf`, `clientSpendOf`, `proofSpendOf`, and the scenes' `issuer`, `upstream`, `prefix`, `grantType` and clients `app`, `keyed` and `holding`.

## Invariants
- Each assertion and proof has a `jti` of its own, so a match on its spend never takes another's.

## Depends on
- The package's scene builder; `conformance` (the fault scene's deployment, the relay and store-wire)
