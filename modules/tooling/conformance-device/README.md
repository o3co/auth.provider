# conformance-device

## Responsibilities
- Owns the conformance scenes of the device area: device authorization, the verification interface and polling (RFC 8628), refusing an approval by a user whose email is not verified, and the audit events of the verification interface.
- Owns the fault scenes of the device area, on a Redis topology and a deployment of their own, each after a control with no fault: a device code decided and redeemed once (internal module `device-code-once`), a subject's revocation boundary refusing a device approved before it (`revocation-boundary`), with what they share (`faults`).
- Sets up the device area's part (the verification page, the attempt limit) on each of the legacy and new targets; a device scene may also name subjects the ledger revokes, as the identity area sets them up.

## Not here
- Scene composition and drivers (`conformance`). Starting the legacy system (`conformance-legacy`). Key, user and client parts (their own areas).

## Offers
- Area `device` and the shape of its part
- Scene builder (builds the key, identity, OAuth and device parts from the form written in a scene)
- The fault run (`conformance:faults`): the `*.faults.case.ts` scenes alone, failing where one did not run, named to the evidence as `@mod/conformance-device#faults` by the run itself; the area's own run and its pattern runs leave them out

## Invariants
- The legacy set-up, and the needs the legacy system cannot provide, live only in `src/legacy.ts`.
- On the new target, the device grant is composed with `session-tokens`, which records its tokens to the session that approved them, as `device-grant` asks to start.
- On the new target, its tokens can be revoked (`tokens.revocation = denylist`, as the device pattern sets it), as `session-tokens` asks to start.
- Touches only the HTTP interface.

## Depends on
- `conformance`, `conformance-legacy`, `conformance-keys`, `conformance-identity`, `conformance-oauth`
