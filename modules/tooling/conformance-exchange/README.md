# conformance-exchange

## Responsibilities
- Owns the conformance scenes of the exchange area: Token Exchange (RFC 8693), its success with and without an actor, the lifetime asked, and its refusals, among them a subject whose email is not verified.
- Covers three kinds of hole by behaviour: a binding washed off, a forged actor, a missed revocation.
- Owns the scene of a subject the ledger revokes across every way to a token: a code redeemed and one not yet, refresh, token exchange, a device's approval polled and one not yet, the back-channel logout token to the session's client, and the fresh login the authorization endpoint then asks for.
- Owns the fault scenes of the exchange area, on a Redis topology and a deployment of their own, each after a control with no fault: a subject's revocation boundary refusing the exchange of a token given before it (internal module `revocation-boundary`), an Apple id_token taken once by the token exchange or as a JWT bearer assertion (internal module `id-token-once`), with what they share (`faults`).
- Sets up the exchange area's part (the actor chain's limit and the lifetime cap) on each of the legacy and new targets, and on the new target Apple's id_tokens taken by both grants for the clients named, outbound reaching Apple through the proxy given.

## Not here
- Scene composition and drivers (`conformance`). Starting the legacy system (`conformance-legacy`). Key, user, client, code-flow and device parts (their own areas).

## Offers
- Area `exchange` and the shape of its part
- Scene builder (builds the key, identity, OAuth and code parts, with refresh, introspection and revocation, from the form written in a scene)
- The fault run (`conformance:faults`): the `*.faults.case.ts` scenes alone, failing where one did not run only with `CONFORMANCE_FAULTS=1`, as CI sets and the script does not; named to the evidence as `@mod/conformance-exchange#faults` by the run itself; the area's own run and its pattern runs leave them out

## Invariants
- The legacy set-up, the needs the legacy system cannot provide, and the differences it answers differently, live only in `src/legacy.ts`.
- A scene whose subject tokens carry no session says so.
- A pattern's app with a user ledger and verified-email leaves out a scene whose subject tokens carry no session, as no source can vouch for the subject's email.
- Touches only the HTTP interface.

## Depends on
- `conformance`, `conformance-legacy`, `conformance-keys`, `conformance-identity`, `conformance-oauth`, `conformance-code`, `conformance-device`
