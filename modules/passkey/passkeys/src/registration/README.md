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
- Where the store writes the record and the list as one, the first ask comes before the write, so a revoked registration writes nothing.

## Depends on
- `webauthn` (the ceremonies); the package's contract and records
