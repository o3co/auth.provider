# webauthn

## Responsibilities
- Runs WebAuthn ceremonies: options, response verification, the signature count and the user handle, by its internal module `ceremony`.
- Keeps passkeys: each subject's user handle, and the credentials registered for it; its internal module `registration` registers them.
- Answers assertions by the passkeys it keeps, and assertions whose challenge and credential the caller keeps.

## Not here
- What an assertion leads to, and the amr it adds (the login and second-factor modules). Issuing tokens. Second-factor credentials (`mfa` keeps them). The routes that register passkeys, and who may register.

## Offers
- `ceremonies`: creation options (a discoverable credential unless asked otherwise) and attestation, request options and assertion. The caller keeps the challenge and the credential and hands them over once.
  - Options also answer the challenge's end, `until`: now on `kernel`'s clock plus `challenge-lifetime`.
  - An answer at or past an `until` handed back is `challenge`; with none, the caller judges the lifetime.
  - A request's challenge says whether it named credentials, and `assert` reads that from it alone: keep it on the server and hand back what was kept, never a value the client sent. One remade from the client's answer, as `passkeys` remakes it, reads as none named; an ending it did not write is `malformed`.
  - Across an update to this release, a challenge kept bare before it reads as none named: its answer passes with a handle, and one without (a second factor's that is not discoverable) is refused, a new challenge then passing.
- `passkeys`: a challenge the same for everyone, made for a requester, and the assertion of a discoverable passkey by that requester → subject, challenge time, user verified, backup eligible; or a refusal.
- `registrations`: options for a subject's new passkey, and keeping the one a response creates → the credential, or a refusal (the ceremony's, `unreadable`, `no-challenge`, `conflict`, `full`).
  - The caller answers for who the subject is; webauthn takes it as given, so only a module that has authenticated the subject may ask.
- `credentialOf`: a value read as a credential in the shape webauthn writes, with its fields alone and the canonical checks and limits of its id, key and handle; nothing for any other value.
- `freshHandle`: a new user handle from the randomness given, by the rule webauthn makes its own by.
- Store interfaces, which the assembly wires. The store never sees what a record holds.
  - Passkeys: credentials and subjects, each by a key webauthn makes, saved once, read, changed from what they hold, kept without end. Needs: no eviction, survives a crash, never rolled back by failover, confirmed reads.
  - Challenges: opened for a lifetime, taken by putting a mark in place. Needs: survives a crash, never rolled back by failover, names derived from the challenge.
- Operator section: `rp-id`, `rp-name`, `origins` (required), `top-origins` (default none), `challenge-lifetime` (10s–10m, default `2m`, written with its unit), `user-verification` (default `preferred`), `max-credentials` (per subject, default 10).
- Test configuration builders, the contract tests of both store interfaces, and a software authenticator behind a browser (`./testing`), which answers options as a browser does and takes twists for refusal tests.

## Invariants
- A challenge is 32 random bytes, taken once, within its lifetime on `kernel`'s clock, whatever the store's expiry. A taken mark stays for the rest of it.
- An assertion's challenge is redeemed by its requester alone; any other is `challenge`, after the challenge is taken. Its record keeps the requester's SHA-256, never the requester.
- Origins match the list exactly: https, or http on `localhost`; never an IP literal. An Android app origin is `android:apk-key-hash:` and the unpadded base64url SHA-256 of its signing certificate, never a top origin.
- An origin that is empty or no URL refuses boot at its place in the list. A reported top origin not listed is refused, and with none listed any frame is, for registration and assertion alike. The relying party ID must match; boot refuses one that is not each web origin's host or a domain it lies under. Algorithms are EdDSA, ES256 and RS256.
- A relying party ID that is a public suffix of several labels (`co.uk`) passes boot: no list of them is kept, and the browser refuses it at the first ceremony.
- The count is compared after the signature verified, and must go up (0 after 0 passes). It is written only over the count judged; a lost race is `raced`.
- `registrations`' creation options require a discoverable credential, as `passkeys` lists none to ask for.
- An assertion whose request named no credential is refused without a user handle (`user-handle`, WebAuthn §7.2 step 6); one whose request named it may carry none. A handle carried must be the credential's.
- `passkeys` refuses an assertion without a user handle before any store is read. The handle must be its holder's, judged after the signature.
- A user handle is 32 random bytes per subject, carrying neither the subject nor a name. Handles and credential ids are written and compared only as unpadded base64url; a credential that would not read back is refused before a write. Transports are kept only as a short list of short strings. A record read in another shape is unavailable.
- A credential id its holder lists is refused at registration. One no holder lists, left by a registration that failed between its two writes or found its subject full, is taken over. Options exclude the subject's own.
- Registration asks for no attestation, so it takes the public key as sent: nothing proves the client holds its private key until the first assertion.
- `conflict` tells the caller that some subject lists an id. Ids are high-entropy, made by the authenticator, so this answers only for an id already known.
- `required` refuses a response without user verification. A backup eligibility other than the registered one is refused.
- A store that cannot tell is unavailable, never a refusal.

## Data
- Passkeys and subjects through the passkey store; challenges through the challenge store.

## Depends on
- `kernel`

## Vocabulary
- holder: a subject's user handle and the ids of its passkeys. passkey: a credential this module keeps for a subject.
