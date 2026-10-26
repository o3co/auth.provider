# acr

Internal module of `conformance-code`: the scenes of the acr a client asks for.

## Responsibilities
- Checks the acr asked by `acr_values`: the first the session meets in the order asked carried into the ID token, the unknown passed over, and none carried when none was asked.
- Checks a claims parameter that is no object refused, and the claims it names but acr ignored.
- Checks a session that falls short sent once to raise it by a second factor, and the acr carried once it is raised; and an acr no way of logging in can meet refused at boot.

## Depends on
- The package's scene builder and browser; `conformance` (the target); `conformance-oauth` (clients); `conformance-second-factor` (the step-up page, raising, the second-factor acr)
