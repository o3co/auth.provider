# mfa-totp

## Responsibilities
- Contributes TOTP (RFC 6238) to `mfa` as a second-factor kind.

## Not here
- Keeping factors, their secrets sealed and their state (`mfa`).
- Transactions, attempt limits and lockout (`mfa-flows`).

## Offers
- A composition definition only, with no contract of its own.
- To `mfa`'s `factorKinds`: kind `totp`, amr `otp`, adding `mfa`, guessable and counting.
- `enroll`: a new secret, shown as base32 with an otpauth URI, the algorithm, digits and period.
- `verify`: valid with the step used as the next state, invalid, or replayed.

## Invariants
- Codes are SHA-1, 6 digits and 30-second steps, on `kernel`'s clock.
- A code is accepted for the current step or one step either side, and refused as invalid otherwise.
- Every step in that window is compared in constant time, so timing does not tell which one matched.
- A step at or before the last one used is refused as replayed, the same code or an older one.
- Replay protection rests on the state `mfa` keeps, which its store keeps through a crash and a failover; restoring the store from a backup brings used steps back.
- The secret is 20 random bytes.
- The otpauth issuer and label prefix are the public origin's host, port included, or `auth` without a public origin.

## Depends on
- `kernel`, `http`, `mfa`

## Vocabulary
- Step: one 30-second period of TOTP, counted from the Unix epoch.
