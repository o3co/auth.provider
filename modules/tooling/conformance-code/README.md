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
- Owns the code flow's fault scenes, on a Redis topology and deployment of their own, each after a no-fault control: a code redeemed once, a refresh token rotated once, a closing session closed, no code, nor a token for a code, issued while the store cannot answer, nothing issued while it cannot write, no boot where it evicts, a subject's revocation boundary refusing from any instance what was made before it, and the bounds left to the operator, recorded; the internal modules are named below.
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
- The scenes of a logout a client starts are the internal module `logout`, those of userinfo `userinfo`, those of the acr asked `acr`, those of the claims a request names beyond its scope `claims`, those of refusing an unverified email `verified-email`, those of a subject the ledger revokes `revocation`, those of clients whose id is the URL of their metadata document `documents`, that of the whole metadata document `discovery`.
- The scenes of redeeming an OpenID Connect code or refresh token are the internal module `redemption`, those of the ID token and the authorization endpoint's answers `id-token`, those of a public client's refresh family bound to its certificate `refresh-certificate`, and those of the space-delimited lists the code flow writes and reads `space-lists`; the rest are the package's.
- The fault scenes are internal modules: `code-once` (a code redeemed once), `refresh-once` (a refresh token rotated once), `session-closing` (a closing session closed), `authorize-unavailable` and `token-unavailable` (no code, and no token for a code, while the store cannot answer), `store-rows` (a store that cannot write or evicts), `boundaries` (the bounds left to the operator), `revocation-boundary` (a subject's revocation boundary); what they share is `faults`.
- The legacy set-up, and the needs the legacy system cannot provide and the differences it answers differently, live only in `src/legacy.ts`.
- The code flow needs access tokens that can be revoked after they are issued (`tokens` is set to denylist).
- Touches only the HTTP interface and boot refusals.

## Depends on
- `conformance`, `conformance-legacy`, `conformance-keys`, `conformance-identity`, `conformance-oauth`, `conformance-second-factor`, `conformance-mtls`
