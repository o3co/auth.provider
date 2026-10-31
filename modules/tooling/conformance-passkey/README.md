# conformance-passkey

## Responsibilities
- Owns the conformance scenes of the passkey area: registering a passkey from a session, and its refusals (no session, a second factor not recent, an origin or a frame not listed, a frame whose page is not reported, a challenge answered twice or past its lifetime, a credential id another account holds, a user not verified when required, the limit of passkeys per user, the store failing).
- Owns the scenes of logging in with a passkey at the token endpoint: tokens for a confidential or a public client, refresh and revocation, the refusals (a client not allowed, a form body, an assertion twice, a count going back, another account's user handle, no user handle, options another client asked for), options the same for anyone and their limit, DPoP binding, the store failing, and refusing a user whose email is not verified (with starting over the users file).
- Owns the scenes of logging in with a passkey into a browser session (`login-passkey`): a session the session's routes take, the refusals alike (options another browser asked, an assertion twice, a credential no one registered), the origin checked and the options' limit, and a verified user let past a second factor or, where it does not count, held by it.
- Owns the scenes of refusing the password of a subject holding a passkey: before a second factor holds the login, and again when a held one resumes, with the passkey witness at a fake ledger the scene runs, as the mode refuses to boot without one.
- Owns the scenes of WebAuthn as a second factor: binding a credential that need not be discoverable, proving it at a login it holds, the refusals (a count that did not go up, a response to another challenge), and an acr asking the amr it proves (`pop`) or one it does not (`hwk`).
- Owns the fault scenes of the passkey area, on a Redis topology and a deployment of their own, each after a control with no fault: a passkey challenge used once (internal module `passkey-challenge-once`), with what they share (`faults`).
- Sets up the passkey area's parts (relying party, origins, framing pages, user verification, challenge lifetime, passkeys per user, the login and its options' limit, the session login and its password rule, WebAuthn as a second factor) on each of the legacy and new targets.
- On the legacy target, DPoP comes with the passkey login when the OAuth part asks for it.
- WebAuthn as a second factor needs the second-factor area's part beside it.
- On a pattern's app that keeps passkeys' witness at a ledger (`passkey-witness-http`), a fake ledger keeps it for every scene: whether a subject is marked and with what token, the first mark, and withdrawing it by its token alone (no clear: passkey-witness-http calls none).

## Not here
- Scene composition and drivers (`conformance`). The software authenticator (`webauthn`'s test tools). Starting the legacy system (`conformance-legacy`). Key, user, OAuth, code and second-factor parts.

## Offers
- Area `passkey` and the shape of its parts
- The fault run (`conformance:faults`): the `*.faults.case.ts` scenes alone, failing where one did not run only with `CONFORMANCE_FAULTS=1`, as CI sets and the script does not; named to the evidence as `@mod/conformance-passkey#faults` by the run itself; the area's own run and its pattern runs leave them out

## Invariants
- The legacy set-up, and the needs the legacy system cannot provide, live only in `src/legacy.ts`.
- A pattern's app with a user ledger and verified-email leaves out a scene of passkey login at the token endpoint: no source can vouch for the subject's email.
- A pattern's app that does not compose `login-passkey` leaves out the scenes of the session login; the legacy target cannot hold them (`passkey-session-login`).
- Touches only the HTTP interface and boot refusals: an operator's reset and the backfill are their packages' tests'.

## Depends on
- `conformance`, `conformance-legacy`, `conformance-oauth`, `ledger-fakes` (the fake passkey witness ledger); in tests, `conformance-code`, `conformance-identity`, `conformance-keys` and `conformance-second-factor` (their areas, with `conformance-code`'s scene builder and `conformance-second-factor`'s test tools), and `webauthn`, for its software authenticator
