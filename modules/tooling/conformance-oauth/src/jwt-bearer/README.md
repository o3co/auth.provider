# jwt-bearer

Internal module of `conformance-oauth`: the scenes of the jwt-bearer grant.

## Responsibilities
- Owns the conformance scenes of the jwt-bearer grant: issuers whose keys are written, linked issuers whose signers' keys a ledger answers, an issuer whose assertions are used up in a ledger shared with another service, and the grant's absence.

## Not here
- Setting the grant up on each target, and the shape of a trusted issuer (the package's area and set-up). Scene composition and drivers (`conformance`).

## Offers
- Scenes only: none is imported.

## Invariants
- A scene about the grant runs only on a target that can trust an outside issuer (`trusted-issuers`), but the one about its absence.
- A shared ledger's scenes run a fake of the deployed wire (the token in `X-Internal-Token`, `{jti, exp}`, 204, 409, 400, 401, 503), the other service using jtis up there as well.
- Touches only the HTTP interface and boot refusals.

## Depends on
- The package's area (`oauthScene`, `oauthArea`); `conformance`, `conformance-keys`, `conformance-identity` in the scenes.
