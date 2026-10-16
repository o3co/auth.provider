# registration

Internal module of `webauthn`: registering passkeys.

## Responsibilities
- Registers passkeys for a subject: options, then the verified response.

## Not here
- The ceremonies (`ceremony`). How records are written (the package's records). Who the subject is (the caller).

## Offers
- `registrationsOver` (ceremonies, records, challenges, user verification, the limit, a fresh handle) → the package's `Registrations`.

## Invariants
- A challenge counts only for the subject it was made for, once. Client data that does not read takes no challenge.
- A subject's handle is made on its first options, and kept.

## Depends on
- `ceremony`; the package's contract and records
