# mfa-webauthn

## Responsibilities
- Contributes WebAuthn as a kind of second factor (`webauthn`), on `webauthn`'s ceremonies.

## Not here
- The ceremonies and their checks (`webauthn`). Keeping factors, challenges and transactions (`mfa`, `mfa-flows`). Passkeys for signing in (`webauthn`).

## Offers
- Contribution to `mfa`'s factor kinds: `webauthn`, adding `mfa`, not guessable, counting.
  - Enrolment: creation options for a credential that need not be discoverable, excluding the subject's WebAuthn factors, for the subject's user handle, showing its name (`subject-attributes`; well formed, 1 to 64 code points, no control or format character), never its email, else `display-name`; its first proof is the attestation.
  - Challenge: request options for the factor's credential, good until `webauthn`'s end (`challenge-lifetime`, `2m` by default) or the caller's when earlier; its proof is the assertion, as JSON. A binding's creation is good until `webauthn`'s end.
- Operator section: `user-verification` (`required`, `preferred` by default, or `discouraged`), `display-name` (the name an authenticator shows for an account with none to show, naming no one; default `Account`).

## Invariants
- A subject's WebAuthn factors share one user handle, made by `webauthn`'s rule (`freshHandle`), apart from its passkeys'; a subject holding none gets a new one.
- The amr is `swk` for a credential that may be backed up, else `hwk` (RFC 8176). Here `hwk` means "not backup eligible"; `webauthn-login`'s `hwk` covers every passkey, whatever its backup eligibility.
- A credential bound twice to one subject is a duplicate. One subject's credential is never compared with another's, even under the same credential id: each factor is checked within its subject's user handle.
- A factor's credential is read as `webauthn` reads its own (`credentialOf`). A credential, a pending secret or a kept challenge that does not read is unavailable, as a store fault; no challenge kept is invalid. An assertion whose count did not go up is replayed; any other refusal is invalid. The factor keeps the count and backup state the assertion gives.
- An authenticator that keeps no count answers alike each time: one proof passes once only because the caller hands each kept challenge over once (`mfa-flows` takes it with the attempt).
- A user who signs in with a passkey can meet this factor with another credential on the same authenticator; to keep the two factors on separate devices, do not compose this module.

## Depends on
- `kernel`, `mfa-extensions` (the kind's contract), `mfa` (composed for it: it stays among this package's dependencies, so adding this kind composes `mfa`), `subject-attributes` (the name shown), `users` (attribute names), `webauthn` (ceremonies)
