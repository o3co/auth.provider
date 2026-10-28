# conformance-identity

## Responsibilities
- Owns the conformance scenes of the identity area: password login (a form or JSON body), missing credentials, return destination, attempt limits, logout, login during a store failure, the audit events of password login, the attempt limit (over it, and unable to count) and logout.
- Owns the scenes of password login against a user ledger asked over HTTP, in the legacy build's HTTP user repository shapes: success, a user it does not hold, its failures, a redirect, a malformed user, and the boot refusal beside users in the settings. A scene's ledger may also look users up by upstream identity, with no lookup by subject.
- A user ledger over HTTP beside users in the settings is a need the legacy build cannot meet.
- A recent-authentication window a scene sets (`recentAuthenticationWindow`) is a need the legacy build cannot meet.
- Owns the fault scenes of password login, on a Redis topology and a deployment of their own, each after a control with no fault: the attempt limit letting no attempt by while the store cannot count (internal module `attempts-unavailable`), a login opening no session while the store cannot answer (`login-unavailable`), an identifier's count holding across a crash, a failover and two instances (`lockout-holds`), with what they share (internal module `faults`).
- Sets up the identity area's parts (public origin, users, login configuration, how a request limit answers while the store fails) on each of the legacy and new targets; the legacy one leaves the last to its own default.
- On the new target, mail, where composed, is accepted to send nothing.
- On a pattern's app that takes users from a ledger (`users-http`), serves the users a scene gives from a fake ledger the app is pointed at, unless the scene sets its own.
- On a pattern's app that takes users from a ledger (`users-http`), a fake ledger holds the scene's users and answers their upstream links by `upstream-url`; a scene with users a ledger cannot hold (a bcrypt hash) is left out as the app's alternative.
- On a pattern's app that keeps mfa's witness at a ledger (`mfa-witness-http`), a fake ledger keeps it for every scene, its own ledger or none: whether a subject is enrolled and by which token, the first mark, withdrawing it by its token alone, and clearing it.
- On a pattern's app composing `verified-email`, a scene that states none of its users' email verified or not has each stated verified, with an address.
- On a pattern's app composing `verified-email`, a user stated either way is given an address where the scene gave none, as `users` keeps the statement only beside one.

## Not here
- Scene composition and drivers (`conformance`). Starting the legacy system (`conformance-legacy`). Key parts (`conformance-keys`).

## Offers
- Area `identity` and the shape of its parts (public origin, users, a user ledger over HTTP, return destination and attempt limits)
- The need for a user ledger over HTTP
- The need for a user ledger over HTTP beside users in the settings
- The fault run (`conformance:faults`): the `*.faults.case.ts` scenes alone, failing where one did not run, named to the evidence as `@mod/conformance-identity#faults` by the run itself; the area's own run and its pattern runs leave them out

## Invariants
- The legacy set-up, and the needs the legacy system cannot provide and the differences it answers differently, live only in `src/legacy.ts`.
- Touches only the HTTP interface and boot refusals.

## Depends on
- `conformance`, `conformance-legacy`, `ledger-fakes` (the fake user ledger and mfa's witness ledger)
