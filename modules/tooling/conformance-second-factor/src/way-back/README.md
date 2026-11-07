# way-back

Internal module of `conformance-second-factor`: the fault scene of a code by mail bound as a way back, then a deployment started again under a required second factor, on one Redis.

## Responsibilities
- Checks that a code by mail whose proof adds no mfa, bound while the second factor was optional (as 0.19 bound it under required too), is listed at no login under required, proves nothing (`400`, `unknown factor`) and lifts no hold its counting factor is under.

## Invariants
- Both starts share the store and the sealing key (`sealKey`), so the second reads what the first sealed.

## Depends on
- The package's scene builder and test tools; `conformance-identity`, `conformance-keys` (the user and the keys); `conformance` (the deployment, the topology and the fake SMTP relay)
