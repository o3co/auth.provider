# grants

Internal module of `conformance-federation`: the scenes of federation grants.

## Responsibilities
- Checks a grant from a client's intent through the user's connection to the upstream token, its refresh, its renewal and its end.
- Checks the refusals: another client's or subject's grant, an answer without origin evidence, another browser or user, a token it cannot hold, a scope wider than the connection's, and fewer scopes where the connection takes no subsets.
- Checks a connection that takes subsets of its scopes, and the lodging limit per client.
- Checks a subject the ledger revokes: its grants and pending intents end, and another subject's stand.

## Offers
- `grantsScene` (the grants' scene at an upstream), `grantsAt` (what a scene does at a deployment reached at a base URL) and `upstreamAt`, for the area's fault scenes; `grantsTarget`, both on a target of its own.

## Depends on
- The package's scene builder, browser and fake upstream; `conformance` (the target); `conformance-identity` (the need for the ledger's route); `conformance-oauth` (clients)
