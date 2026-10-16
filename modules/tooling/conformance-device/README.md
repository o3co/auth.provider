# conformance-device

## Responsibilities
- Owns the conformance scenes of the device area: device authorization, the verification interface and polling (RFC 8628), refusing an approval by a user whose email is not verified, and the audit events of the verification interface.
- Sets up the device area's part (the verification page, the attempt limit) on each of the legacy and new targets.

## Not here
- Scene composition and drivers (`conformance`). Starting the legacy system (`conformance-legacy`). Key, user and client parts (their own areas).

## Offers
- Area `device` and the shape of its part
- Scene builder (builds the key, identity, OAuth and device parts from the form written in a scene)

## Invariants
- The legacy set-up, and the needs the legacy system cannot provide, live only in `src/legacy.ts`.
- Touches only the HTTP interface.

## Depends on
- `conformance`, `conformance-legacy`, `conformance-keys`, `conformance-identity`, `conformance-oauth`
