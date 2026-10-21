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
  - A registration answers when its challenge was made (`challengedAt`). `listed` (id, nickname, transports, backup state, and when registered where kept), `renamed` (`renamed` / `unknown`) and `removed` (`removed`: this call ended it; `empty`: none left) take only the subject's own; they are optional in the contract until their callers are written.
- Store interfaces, which the assembly wires. The store never sees what a record holds.
  - Passkeys: credentials and subjects, each by a key passkeys makes, saved once, read, changed from what they hold, kept without end. Needs: no eviction, survives a crash, never rolled back by failover, confirmed reads.
  - Challenges: opened for a lifetime, taken by putting a mark in place. Needs: survives a crash, never rolled back by failover, names derived from the challenge.
- Operator section: `user-verification` (default `preferred`), `max-credentials` (per subject, default 10).
- `./testing`: the section's test configuration builder, and the contract tests of both store interfaces.

## Invariants
- A challenge is taken once, within `webauthn`'s `lifetimeMs` on `kernel`'s clock, whatever the store's expiry; a taken mark stays for the rest of it. An assertion's challenge is redeemed by its requester alone; any other is `challenge`, after the challenge is taken. Its record keeps the requester's SHA-256, never the requester.
- `registrations`' creation options require a discoverable credential, as `passkeys` lists none to ask for. `passkeys` refuses an assertion without a user handle before any store is read; the handle must be its holder's, judged after the signature.
- A user handle is made on a subject's first options and kept. Handles and credential ids are written and compared only in `webauthn`'s canonical form; a credential that would not read back is refused before a write. A record read in another shape is unavailable.
- A credential id its holder lists is refused at registration. One no holder lists, left by a registration that failed between its two writes or found its subject full, is taken over. Options exclude the subject's own. `conflict` tells the caller that some subject lists an id; ids are high-entropy, made by the authenticator, so this answers only for an id already known.
- The count is written only over the count judged; a lost race is `raced`.
- A removed passkey leaves its holder's list, which ends its use, and its record is stripped to its subject: no key, count or name. Every read takes it as removed: no passkey (`unknown-credential`), a count `raced`, an id a new registration may take over. A record only another subject holds is never stripped.
- A store that cannot tell is unavailable (`passkeys`), never a refusal.

## Data
- Passkeys and subjects through the passkey store; challenges through the challenge store. Their keys are the ones `webauthn` made before this package, so the records kept stay readable.

## Depends on
- `kernel`, `webauthn` (the ceremonies, the credential's form)

## Vocabulary
- holder: a subject's user handle and the ids of its passkeys. passkey: a credential this package keeps for a subject.
