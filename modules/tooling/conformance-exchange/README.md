# conformance-exchange

## Responsibilities
- Owns the conformance scenes of the exchange area: Token Exchange (RFC 8693), its success with and without an actor, the lifetime asked, and its refusals, among them a subject whose email is not verified.
- Covers three kinds of hole by behaviour: a binding washed off, a forged actor, a missed revocation.
- Owns the scene of a subject the ledger revokes across every way to a token: a code redeemed and one not yet, refresh, token exchange, a device's approval polled and one not yet, the back-channel logout token to the session's client, and the fresh login the authorization endpoint then asks for.
- Sets up the exchange area's part (the actor chain's limit and the lifetime cap) on each of the legacy and new targets.

## Not here
- Scene composition and drivers (`conformance`). Starting the legacy system (`conformance-legacy`). Key, user, client, code-flow and device parts (their own areas).

## Offers
- Area `exchange` and the shape of its part
- Scene builder (builds the key, identity, OAuth and code parts, with refresh, introspection and revocation, from the form written in a scene)

## Invariants
- The legacy set-up, the needs the legacy system cannot provide, and the differences it answers differently, live only in `src/legacy.ts`.
- A scene whose subject tokens carry no session says so.
- A pattern's app with a user ledger and verified-email leaves out a scene whose subject tokens carry no session, as no source can vouch for the subject's email.
- Touches only the HTTP interface.

## Depends on
- `conformance`, `conformance-legacy`, `conformance-keys`, `conformance-identity`, `conformance-oauth`, `conformance-code`, `conformance-device`
