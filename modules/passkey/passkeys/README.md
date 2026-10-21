# passkeys

## Responsibilities
- Keeps passkeys: each subject's user handle, and the credentials registered for it; its internal module `registration` registers them.
- Answers assertions by the passkeys it keeps, through `webauthn`'s ceremonies.

## Not here
- The ceremonies and the relying party: `webauthn`. What an assertion leads to, and the amr it adds (the login and second-factor modules). The routes that register passkeys, and who may register.

## Offers
- `passkeys`: a challenge the same for everyone, made for a requester, and the assertion of a discoverable passkey by that requester → subject, challenge time, user verified, backup eligible; or a refusal.
- `registrations`: options for a subject's new passkey, and keeping the one a response creates → the credential, or a refusal (the ceremony's, `unreadable`, `no-challenge`, `conflict`, `full`).
  - The caller answers for who the subject is; passkeys takes it as given, so only a module that has authenticated the subject may ask.
- Operator section: `user-verification` (default `preferred`), `max-credentials` (per subject, default 10).
- `./testing`: the section's test configuration builder.

## Invariants
- A challenge is taken once, within `webauthn`'s `lifetimeMs` on `kernel`'s clock, whatever the store's expiry; a taken mark stays for the rest of it. An assertion's challenge is redeemed by its requester alone; any other is `challenge`, after the challenge is taken. Its record keeps the requester's SHA-256, never the requester.
- `registrations`' creation options require a discoverable credential, as `passkeys` lists none to ask for. `passkeys` refuses an assertion without a user handle before any store is read; the handle must be its holder's, judged after the signature.
- A user handle is made on a subject's first options and kept. Handles and credential ids are written and compared only in `webauthn`'s canonical form; a credential that would not read back is refused before a write. A record read in another shape is unavailable.
- A credential id its holder lists is refused at registration. One no holder lists, left by a registration that failed between its two writes or found its subject full, is taken over. Options exclude the subject's own. `conflict` tells the caller that some subject lists an id; ids are high-entropy, made by the authenticator, so this answers only for an id already known.
- The count is written only over the count judged; a lost race is `raced`.
- A store that cannot tell is unavailable (`passkeys`), never a refusal.

## Data
- Passkeys and subjects through `webauthn`'s passkey store; challenges through its challenge store. Their keys are the ones `webauthn` made before this package, so the records kept stay readable.

## Depends on
- `kernel`, `webauthn` (the ceremonies, the credential's form, the stores)

## Vocabulary
- holder: a subject's user handle and the ids of its passkeys. passkey: a credential this package keeps for a subject.
