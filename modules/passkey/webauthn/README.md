# webauthn

## Responsibilities
- Runs WebAuthn ceremonies for its relying party: options, response verification, the signature count and the user handle, by its internal module `ceremony`.
- Owns the form of a credential and of a user handle that ceremonies take and answer.

## Not here
- Keeping passkeys, their subjects and their challenges (`passkeys`). What an assertion leads to, and the amr it adds (the login and second-factor modules). Issuing tokens. Second-factor credentials (`mfa` keeps them).

## Offers
- `ceremonies`: creation options (a discoverable credential unless asked otherwise) and attestation, request options and assertion, and how long a challenge can be answered (`lifetimeMs`). The caller keeps the challenge and the credential and hands them over once. `challengeOf` reads the challenge a response answers.
  - Options also answer the challenge's end, `until`: now on `kernel`'s clock plus `challenge-lifetime`. An answer at or past an `until` handed back is `challenge`; with none, the caller judges the lifetime.
  - A request's challenge says whether it named credentials, and `assert` reads that from it alone: keep it on the server and hand back what was kept, never a value the client sent. One remade from the client's answer, as `passkeys` remakes it, reads as none named; an ending it did not write is `malformed`.
  - A challenge kept bare before this release reads as none named: an answer without a handle is refused, and a new challenge passes.
- `credentialOf`: a value read as a credential in the shape webauthn writes, with its fields alone and the canonical checks and limits of its id, key and handle (`isCanonical`, `credentialLimits`); nothing for any other value. `freshHandle`: a new user handle from the randomness given, by the rule webauthn makes its own by.
- Operator section: `rp-id`, `rp-name`, `origins` (required), `top-origins` (default none), `challenge-lifetime` (10s–10m, default `2m`, written with its unit).
- Test configuration builders, the ceremonies over a relying party a test gives (`testCeremonies`), and a software authenticator behind a browser (`./testing`), which answers options as a browser does and takes twists for refusal tests.

## Invariants
- A challenge is 32 random bytes, answered within `challenge-lifetime` of its making on `kernel`'s clock.
- Origins match the list exactly: https, or http on `localhost` (refused at boot in production); never an IP literal. An Android app origin is `android:apk-key-hash:` and the unpadded base64url SHA-256 of its signing certificate, never a top origin. A relying party ID that is a public suffix of several labels (`co.uk`) passes boot: no list of them is kept, and the browser refuses it at the first ceremony.
- An origin that is empty or no URL refuses boot at its place in the list. A reported top origin not listed is refused, and with none listed any frame is, for registration and assertion alike. The relying party ID must match; boot refuses one that is not each web origin's host or a domain it lies under. Algorithms are EdDSA, ES256 and RS256.
- The count is compared after the signature verified, and must go up (0 after 0 passes).
- An assertion whose request named no credential is refused without a user handle (`user-handle`, WebAuthn §7.2 step 6); one whose request named it may carry none. A handle carried must be the credential's.
- A user handle is 32 random bytes, carrying neither the subject nor a name. Handles and credential ids are compared only as unpadded base64url. Transports are taken only as a short list of short strings.
- Creation asks for no attestation, so it takes the public key as sent: nothing proves the client holds its private key until the first assertion. `required` refuses a response without user verification. A backup eligibility other than the credential's is refused.

## Data
- None: the caller keeps the challenges and the credentials.

## Depends on
- `kernel`
