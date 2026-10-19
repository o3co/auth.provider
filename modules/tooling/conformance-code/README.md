# conformance-code

## Responsibilities
- Owns the conformance scenes of the code flow area: the authorization endpoint and its consent step, code redemption, refresh and its binding, acr, and the session grant.
- Owns the scenes of a logout the client starts and the telling of the session's clients.
- Owns the scenes of the metadata document's code flow and logout items, and of clients whose id is the URL of their metadata document.
- Owns the scenes of refusing users whose email is not verified, and a client that is not first-party when consent cannot ask.
- Owns the scenes of the audit events of consent and code redemption.
- Owns the scenes of what a subject's revocation by the ledger ends.
- Sets up the code flow area's parts (consent step, refresh, acr table, session grant, metadata document clients, logout with the back-channel origins allowed) on each of the legacy and new targets.
- A code flow part can leave out the consent step.
- If a second-factor part is present, the code flow set-up also includes the acr bridge.

## Not here
- Scene composition and drivers (`conformance`). Starting the legacy system (`conformance-legacy`). Key, user, client and second-factor parts (their own areas).

## Offers
- Area `code` and the shape of its parts
- Scene builder (builds the key, identity, OAuth, second-factor and code parts from the form written in a scene)
- Test tools (`./testing`): a logged-in browser, and requests to the authorization endpoint

## Invariants
- The scenes of a logout a client starts are the internal module `logout`, those of userinfo `userinfo`, those of refusing an unverified email `verified-email`, and those of a subject the ledger revokes `revocation`; the rest are the package's.
- The legacy set-up, and the needs the legacy system cannot provide and the differences it answers differently, live only in `src/legacy.ts`.
- The code flow needs access tokens that can be revoked after they are issued (`tokens` is set to denylist).
- Touches only the HTTP interface and boot refusals.

## Depends on
- `conformance`, `conformance-legacy`, `conformance-keys`, `conformance-identity`, `conformance-oauth`, `conformance-second-factor`, `conformance-mtls`
