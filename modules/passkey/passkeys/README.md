# passkeys

## Responsibilities
- Keeps passkeys: each subject's user handle, and the credentials registered for it; its internal module `registration` registers them, and `records` reads and writes them in the shape written.
- Answers assertions by the passkeys it keeps, through `webauthn`'s ceremonies; its internal module `challenges` keeps the challenges both answer.
- Keeps a witness's mark in line with whether each subject holds a passkey, so losing the store never reads as holding none; its internal module `holders` settles them.

## Not here
- The ceremonies and the relying party: `webauthn`. What an assertion leads to, and the amr it adds (the login and second-factor modules). The routes that register passkeys, and who may register.

## Offers
- `passkeys`: a challenge the same for everyone, made for a requester, and the assertion of a discoverable passkey by that requester → subject, challenge time, user verified, backup eligible; or a refusal.
- `registrations`: options for a subject's new passkey, and keeping the one a response creates → the credential, or a refusal (the ceremony's, `unreadable`, `no-challenge`, `conflict`, `full`, `revoked`).
  - A caller's check (`admitted`) is asked before the record is written and once after; its write's record (by token) becomes a passkey only as the last write, both asks admitting. A `false` (`revoked`), a throw or a failed write ends it, best effort; what that leaves open, the internal module `registration` says.
  - The caller answers for who the subject is: only a module that authenticated it may ask.
  - A registration answers when its challenge was made (`challengedAt`). `listed` (id, nickname, transports, backup state, and when registered where kept), `renamed` (`renamed` / `unknown`) and `removed` (`removed`: this call ended it; `empty`: none left) take only the subject's own.
- `passkeyHolders`, taken only by `login-passkey` and `passkey-reset`: `held` (settled first), `cleared` (ends every passkey of the subject, making its holder where it has none, and has its mark go → how many it ended), `settle`, and `witnessed` (whether a witness is composed).
- Extension point `passkeyWitnesses` (at most one, two refusing boot): `read`, `enroll` (set-if-absent by token), `withdraw` (only that token's mark) and `markedWith` (the mark's token). Audit event `passkey.enrollment_inconsistent` (`at`), declared in `./audit-events`.
- Store interfaces, which the assembly wires. The store never sees what a record holds.
  - Passkeys: credentials and subjects, each by a key passkeys makes, saved once, read, changed from what they hold, kept without end; records of both spaces and the ones a change watches from them changed as one (`updateTogether`), which boot requires. Needs: no eviction, survives a crash, never rolled back by failover, confirmed reads.
  - Challenges: opened for a lifetime, taken by putting a mark in place. Needs: survives a crash, never rolled back by failover, names derived from the challenge.
- Operator section: `user-verification` (default `preferred`), `max-credentials` (per subject, default 10).
- `./testing`: the section's test configuration builder, the contract tests of both store interfaces, a witness in memory (`passkeyWitnessStandIn`) and the witness's contract test (`passkeyWitnessContract`).

## Invariants
- A challenge is taken once, within `webauthn`'s `lifetimeMs` on `kernel`'s clock, whatever the store's expiry. An assertion's challenge is redeemed by its requester alone; any other is `challenge`, after the challenge is taken. Its record keeps the requester's SHA-256, never the requester: the assertion makes the digest and compares it.
- `registrations`' creation options require a discoverable credential, as `passkeys` lists none to ask for. `passkeys` refuses an assertion without a user handle before any store is read; the handle must be its holder's, judged after the signature.
- A user handle is made on a subject's first options, or by `cleared` where the subject has no holder, and kept; a credential is listed only on the holder whose handle it was made under. A credential that would not read back is refused before a write. A record read in another shape is unavailable.
- A credential id its holder lists is refused at registration. One no holder lists (removed, or left by 0.18) is taken over in the same write. Options exclude the subject's own. `conflict` tells the caller that some subject lists an id; ids are high-entropy, made by the authenticator: it answers only for an id known.
- The count is written only over the count judged; a lost race is `raced`.
- A registration writes the record and the list together, as a removal, an end and a clear change them: in what 0.19 writes, a list names an id exactly while its record names the subject, pending or a passkey. An orphan record or an old entry 0.18 left stays the accepted exception.
- A pending record is no passkey to every read: none to assert (`unknown-credential`), list, rename or count.
- A removed passkey leaves its holder's list, which ends its use, and its record is stripped to its subject: no key, count or name. Every read takes it as removed: no passkey (`unknown-credential`), a count `raced`, an id a new registration may take over. A record only another subject holds is never stripped.
- A store that cannot tell is unavailable (`passkeys`), never a refusal; so is a witness that cannot read or write, wherever a settle runs.
- With a witness, a registration and a removal settle after their write: a registration whose settle fails keeps the passkey written and answers unavailable. A mark beside no passkey goes only by the call that emptied the list (a last removal, an end, `cleared`), as the internal module `holders` says; anywhere else it is recorded as inconsistent and unavailable, as the store may have lost them.

## Data
- Passkeys and subjects through the passkey store; challenges through the challenge store. Their keys are the ones `webauthn` made before this package, so the records kept stay readable.

## Depends on
- `kernel`, `audit`, `webauthn` (the ceremonies, the credential's form)

## Vocabulary
- holder: a subject's user handle, the ids of its passkeys, and its fence, which each write that empties the list moves on, never back. passkey: a credential this package keeps for a subject.
