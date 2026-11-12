# registration

Internal module of `passkeys`: registering passkeys.

## Responsibilities
- Registers passkeys for a subject: options, then the verified response.

## Not here
- The ceremonies (`webauthn`). How records are written (the package's records). Who the subject is (the caller).

## Offers
- `registrationsOver` (ceremonies, records, challenges, user verification, the limit, a fresh handle) → the package's `Registrations`.
- A caller's check (`admitted`) is asked before the record is written and once after; its write's record (by token) becomes a passkey only as the last write, both asks admitting. A `false` (`revoked`), a throw or a failed write ends it, best effort; what that leaves open, the invariants below say.
- A registration answers when its challenge was made (`challengedAt`). `listed` (id, nickname, transports, backup state, and when registered where kept), `renamed` (`renamed` / `unknown`) and `removed` (`removed`: this call ended it; `empty`: none left) take only the subject's own.

## Invariants
- A challenge counts only for the subject it was made for, once. Client data that does not read takes no challenge.
- A subject's handle is made on its first options, and kept. The options name the subject as the account's name and display name, which the authenticator keeps and may show.
- A passkey is made usable only after both of the caller's asks admitted it; anything stopping the registration before leaves its record pending.
- The first ask comes before the record and its listing are written, as one, so a revoked registration writes nothing.
- What is left open: a revocation after the second ask is not seen; a registration stopped, or failing to end, leaves its record pending: if listed, it counts toward `max-credentials` until removed or `cleared`.
- A credential id its holder lists is refused at registration; one no holder lists (removed, or left by 0.18) can be registered. Options exclude the subject's own. `conflict` tells the caller that some subject lists an id; ids are high-entropy, made by the authenticator: it answers only for an id known.
- The count is written only over the passkey judged, its subject, key and count; a lost race, or its id taken over by another meanwhile, is `raced`.

## Depends on
- `webauthn` (the ceremonies); the package's contract and records, and the internal modules `challenges` and `holders` (their types)
