# link

Internal module of `conformance-federation`: the scenes of linking an upstream identity to the account logged in.

## Responsibilities
- Checks that a link started from the deployment's own page by a logged-in browser ties the identity to that account, so a later login through the upstream opens it.
- Checks the refusals: no session, a start from another site, an identity another account holds, a callback after the browser logged in as another account or out, and a login started without asking to link.
- Checks the audit events of a link, where the target lets a scene read them: one linked for the account it started for, and one refused with its reason, neither telling the upstream subject.
- Checks that a link asks a sign-in within the recent-authentication window, at its callback and again at a start, where the target lets a scene set the window (`conformance-identity`'s `recentAuthenticationWindow`).

## Depends on
- The package's scene builder, browser and fake upstream; `conformance-identity`'s need for the window
