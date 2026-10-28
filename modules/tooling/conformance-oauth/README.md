# conformance-oauth

## Responsibilities
- Owns the conformance scenes of the OAuth endpoints area: client credentials, introspection and revocation, jwt-bearer (in the internal module `jwt-bearer`), DPoP, the metadata document, tokens refused to users whose email is not verified, the audit events of issuing and revoking tokens.
- Owns the scenes of the token, introspection and revocation endpoints' refusals carrying no client's secret, no other client's token and no part of the signing key.
- Owns the scenes of cross-origin requests to the token and revocation endpoints, the metadata documents and the key set (the key set's here, as the keys area cannot compose identity's origins without a cycle).
- Owns the fault scenes of the OAuth endpoints, on a Redis topology and a deployment of their own, each after a control with no fault: a JWT bearer assertion's `jti` spent once (internal module `assertion-once`), a client assertion's `jti` spent once (`client-assertion-once`), a DPoP proof's `jti` spent once (`dpop-once`), with what they share (internal module `faults`).
- Sets up the OAuth area's parts (issuer, clients, a client's binding requirement, introspection, revocation, trusted issuers and their profile, DPoP, the metadata document, requiring a verified email) on each of the legacy and new targets.
- The set-up of clients that receive the code flow (clients with a redirect URI) also lives here.

## Not here
- Scene composition and drivers (`conformance`). Starting the legacy system (`conformance-legacy`). Key and user parts (`conformance-keys`, `conformance-identity`). Code flow scenes (`conformance-code`).

## Offers
- Area `oauth` and the shape of its parts
- Scene builder (builds the key parts and the OAuth parts from the form written in a scene)
- The scene builder also takes store marks
- The fault run (`conformance:faults`): the `*.faults.case.ts` scenes alone, failing where one did not run, named to the evidence as `@mod/conformance-oauth#faults` by the run itself; the area's own run and its pattern runs leave them out

## Invariants
- The legacy set-up, and the needs the legacy system cannot provide and the differences it answers differently, live only in `src/legacy.ts`.
- The new system always composes subject revocation and its check on tokens, which `tokens` requires.
- The new set-up composes `client-credentials` only where a scene's client is allowed the grant, as boot refuses a grant a client is allowed that nothing composed serves.
- A scene registers only the clients of its own grants; a client there only to be refused or to authenticate is allowed no grant.
- A scene about DPoP, the jwt-bearer grant or resource indicators being absent says so (`false`).
- The new set-up of a scene about DPoP, the jwt-bearer grant or resource indicators being absent names that module as one the scene is without.
- A pattern's app with a user ledger and verified-email leaves out a jwt-bearer scene: no source can vouch for the subject's email.
- Touches only the HTTP interface and boot refusals.

## Depends on
- `conformance`, `conformance-legacy`, `conformance-keys`; `conformance-identity` in the scenes (users, the origins allowed across origins)
