# faults

Internal module of `conformance-oauth`: what the area's fault scenes share in its words, its scene and the store writes a fault is about; the deployment, the waits and the repointing around a fault are `conformance`'s (`fault-scene`).

## Responsibilities
- Gives the JWT bearer grant's scene on the Redis store, one client trusting one issuer, and runs a scene on a deployment of its own on that scene unless it names another.
- Signs an assertion of that issuer with a `jti` of its own, and sends it to an instance's token endpoint.
- Names an assertion's spend as the relay matches it: its record placed under the issuer's and the `jti`'s name in `jwt-bearer-store.spent`.

## Offers
- `faultScene`, `on` (`conformance`'s, on `faultScene` by default), `assertion`, `grantAt`, `said`, `spendOf`, and the scene's `issuer`, `upstream`, `prefix`, `grantType` and client `app`.

## Invariants
- Each assertion has a `jti` of its own, so a match on its spend never takes another's.

## Depends on
- The package's scene builder; `conformance` (the fault scene's deployment, the relay and store-wire)
