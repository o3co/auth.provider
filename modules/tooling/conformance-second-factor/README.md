# conformance-second-factor

## Responsibilities
- Owns the conformance scenes of the second-factor area: second factor at login (by a form or a JSON body), enrollment, naming factors, step-up, lockout, store failure, the audit events they record.
- Owns the scenes of a code by mail as a second factor (binding by the long code, a login let in by six digits, a wrong code refused).
- Owns the scenes of a user's own release of the lockout (released after a recovery code, refused without one, refused while the account was not revoked after the first counted failure, a fixed hold naming when its factors may be bound again).
- Owns the scene of a login a second factor holds when the ledger revokes its subject (its transaction answers `login_required`, and the right code opens no session).
- Sets up the second-factor area's parts (optional or required, a code by mail, and the lockout's numbers) on each of the legacy and new targets.
- Runs the conformance base's fake SMTP relay for its mail scenes, each run.
- Tells both targets where the fake SMTP relay listens.

## Not here
- Scene composition and drivers (`conformance`). Starting the legacy system (`conformance-legacy`). Key and user parts.

## Offers
- Area `second-factor` and the shape of its parts
- Location of the raise page (`stepUpPage`)
- Test tools (`./testing`): TOTP codes, a browser that keeps cookies and posts a form or JSON (with the answer's headers, where a scene reads them), an interface that starts a scene, enrols a user and reads the audit events the target sends, one that begins a binding and, where the target asks a binding proof, sends the code mailed to the user, one that passes login with a recovery code, one that raises with TOTP, the acr value a second factor satisfies

## Invariants
- The legacy set-up, and the differences the legacy system answers differently, live only in `src/legacy.ts`.
- Touches only the HTTP interface and boot refusals.

## Depends on
- `conformance`, `conformance-legacy`
