# acr

Internal module of `conformance-code`: the scenes of the acr a client asks for.

## Responsibilities
- Checks the acr asked by `acr_values`, voluntarily: the first the session meets in the order asked carried into the ID token, the unknown passed over, the session's current acr where none known is met, and none carried when none was asked.
- Checks a claims parameter's acr: essential and met carried, essential and unknown or unmet refused, never met by another request's voluntary values, a value holding a blank naming no acr; not essential taken as voluntary; a claims parameter or acr of no shape Core gives refused, and the claims it names but acr ignored.
- Checks a session that falls short sent once to raise it by a second factor, and the acr carried once it is raised; a voluntary acr passed over under `prompt=none` or back unraised, and an essential one held; and an acr no way of logging in can meet refused at boot.

## Depends on
- The package's scene builder and browser; `conformance` (the target); `conformance-oauth` (clients); `conformance-second-factor` (the step-up page, raising, the second-factor acr)
