# registration

Internal module of `passkeys`: registering passkeys.

## Responsibilities
- Registers passkeys for a subject: options, then the verified response.

## Not here
- The ceremonies (`webauthn`). How records are written (the package's records). Who the subject is (the caller).

## Offers
- `registrationsOver` (ceremonies, records, challenges, user verification, the limit, a fresh handle) → the package's `Registrations`.

## Invariants
- A challenge counts only for the subject it was made for, once. Client data that does not read takes no challenge.
- A subject's handle is made on its first options, and kept.
- A passkey is made usable only after both of the caller's asks admitted it; anything stopping the registration before leaves its record pending.
- The first ask comes before the record and its listing are written, as one, so a revoked registration writes nothing.
- What is left open: a revocation after the second ask is not seen; a registration stopped, or failing to end, leaves its record pending: if listed, it counts toward `max-credentials` until removed or `cleared`.

## Depends on
- `webauthn` (the ceremonies); the package's contract and records
