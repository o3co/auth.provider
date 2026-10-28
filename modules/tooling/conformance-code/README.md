# conformance-code

## Responsibilities
- Owns the conformance scenes of the code flow area: the authorization endpoint and its consent step, code redemption, refresh and its binding, acr, and the session grant.
- Owns the scenes of a logout the client starts and the telling of the session's clients.
- Owns the scenes of the metadata document's code flow and logout items, and of clients whose id is the URL of their metadata document.
- Owns the scenes of refusing users whose email is not verified, and a client that is not first-party when consent cannot ask.
- Owns the scenes of the audit events of consent and code redemption.
- Owns the scenes of a password login meeting a client's demand for a fresh login (internal module `fresh-login`).
- Owns the scenes of what a subject's revocation by the ledger ends.
- Owns the scenes of the code flow's answers, its refusals, discovery and userinfo's among them, carrying no client's secret, no user's password or token, and no part of the signing key.
- Owns the fault scenes of the code flow, on a Redis topology and a deployment of its own, each after a control with no fault: a code redeemed once (internal module `code-once`), a refresh token rotated once (`refresh-once`), a closing session closed (`session-closing`), with what they share (internal module `faults`).
- Sets up the code flow area's parts (consent step, refresh, acr table, session grant, metadata document clients, logout with the back-channel origins allowed, beside the documents' hosts where both are on, how often pending closes are gone on with) on each of the legacy and new targets.
- A code flow part can leave out the consent step.
- If a second-factor part is present, the code flow set-up also includes the acr bridge.

## Not here
- Scene composition and drivers (`conformance`). Starting the legacy system (`conformance-legacy`). Key, user, client and second-factor parts (their own areas).

## Offers
- Area `code` and the shape of its parts
- Scene builder (builds the key, identity, OAuth, second-factor and code parts from the form written in a scene)
- The fault run (`conformance:faults`): the `*.faults.case.ts` scenes alone, failing where one did not run; named to the evidence as `@mod/conformance-code#faults` by the run itself, the area's own run and its pattern runs leaving them out
- Test tools (`./testing`): a logged-in browser, requests to the authorization endpoint, and `succeeded` (a set-up's answer read only when it succeeded, else the scene fails naming what answered, its status and its body's start)

## Invariants
- The scenes of a logout a client starts are the internal module `logout`, those of userinfo `userinfo`, those of the acr asked `acr`, those of the claims a request names beyond its scope `claims`, those of refusing an unverified email `verified-email`, those of a subject the ledger revokes `revocation`, and those of clients whose id is the URL of their metadata document `documents`; the rest are the package's.
- The fault scenes of a code redeemed once are the internal module `code-once`, those of a refresh token rotated once `refresh-once`, those of a closing session closed `session-closing`, and what they share `faults`.
- The legacy set-up, and the needs the legacy system cannot provide and the differences it answers differently, live only in `src/legacy.ts`.
- The code flow needs access tokens that can be revoked after they are issued (`tokens` is set to denylist).
- Touches only the HTTP interface and boot refusals.

## Depends on
- `conformance`, `conformance-legacy`, `conformance-keys`, `conformance-identity`, `conformance-oauth`, `conformance-second-factor`, `conformance-mtls`
