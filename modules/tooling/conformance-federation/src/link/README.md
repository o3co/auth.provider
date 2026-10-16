# link

Internal module of `conformance-federation`: the scenes of linking an upstream identity to the account logged in.

## Responsibilities
- Checks that a link started from the deployment's own page by a logged-in browser ties the identity to that account, so a later login through the upstream opens it.
- Checks the refusals: no session, a start from another site, an identity another account holds, a callback after the browser logged in as another account or out, and a login started without asking to link.

## Depends on
- The package's scene builder, browser and fake upstream
