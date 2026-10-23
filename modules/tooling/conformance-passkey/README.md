# conformance-passkey

## Responsibilities
- Owns the conformance scenes of the passkey area: registering a passkey from a session, and its refusals (no session, a second factor not recent, an origin or a frame not listed, a frame whose page is not reported, a challenge answered twice or past its lifetime, a credential id another account holds, a user not verified when required, the limit of passkeys per user, the store failing).
- Owns the scenes of logging in with a passkey at the token endpoint: tokens for a confidential or a public client, refresh and revocation, the refusals (a client not allowed, a form body, an assertion twice, a count going back, another account's user handle, no user handle, options another client asked for), options the same for anyone and their limit, DPoP binding, the store failing, and refusing a user whose email is not verified (with starting over the users file).
- Owns the scenes of WebAuthn as a second factor: binding a credential that need not be discoverable, proving it at a login it holds, the refusals (a count that did not go up, a response to another challenge), and an acr asking the amr it proves (`pop`) or one it does not (`hwk`).
- Sets up the passkey area's parts (relying party, origins, framing pages, user verification, challenge lifetime, passkeys per user, the login and its options' limit, WebAuthn as a second factor) on each of the legacy and new targets.
- On the legacy target, DPoP comes with the passkey login when the OAuth part asks for it.
- WebAuthn as a second factor needs the second-factor area's part beside it.
- On a pattern's app that keeps passkeys' witness at a ledger (`passkey-witness-http`), a fake ledger keeps it for every scene: whether a subject is marked, the first mark, withdrawing it by its token alone, and clearing it.

## Not here
- Scene composition and drivers (`conformance`). The software authenticator (`webauthn`'s test tools). Starting the legacy system (`conformance-legacy`). Key, user, OAuth, code and second-factor parts.

## Offers
- Area `passkey` and the shape of its parts

## Invariants
- The legacy set-up, and the needs the legacy system cannot provide, live only in `src/legacy.ts`.
- A pattern's app with a user ledger and verified-email leaves out a scene of passkey login at the token endpoint: no source can vouch for the subject's email.
- Touches only the HTTP interface and boot refusals.

## Depends on
- `conformance`, `conformance-legacy`, `conformance-oauth`; `webauthn` in tests, for its software authenticator
