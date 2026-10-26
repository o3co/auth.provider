# jwt-bearer

Internal module of `conformance-oauth`: the scenes of the jwt-bearer grant.

## Responsibilities
- Owns the conformance scenes of the jwt-bearer grant: issuers whose keys are written, linked issuers whose signers' keys a ledger answers (self-issued signers among them), an issuer whose assertions are used up in a ledger shared with another service, each issuer's own policy (an issuer two organisations share held to its conditions, a ceiling, a PS256 key), a request naming no client taken by its issuer's client, and the grant's absence.
- Owns the scenes of an issuer taking ID-JAGs: its client, scope, resources and key, DPoP proofs checked by the endpoint first, and what else answers alike with it or none.

## Not here
- Setting the grant up on each target, and the shape of a trusted issuer (the package's area and set-up). Scene composition and drivers (`conformance`).

## Offers
- Scenes only: none is imported.

## Invariants
- A scene about the grant runs only on a target that can trust an outside issuer (`trusted-issuers`), but the one about its absence.
- A shared ledger's scenes run a fake of the deployed wire (the token in `X-Internal-Token`, `{jti, exp}`, 204, 409, 400, 401, 503), the other service using jtis up there as well.
- The ID-JAG scenes run on the new target alone: the legacy build takes no trusted issuer, and a comparison with its own profile is not promised.
- Touches only the HTTP interface and boot refusals.

## Depends on
- The package's area (`oauthScene`, `oauthArea`); `conformance`, `conformance-keys`, `conformance-identity` in the scenes.
