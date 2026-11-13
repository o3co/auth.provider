# mfa-totp

## Responsibilities
- Contributes TOTP (RFC 6238) to `mfa` as a second-factor kind.

## Not here
- Keeping factors, their secrets sealed and their state (`mfa`).
- Transactions, attempt limits and lockout (`mfa-flows`).

## Offers
- A composition definition only, with no contract of its own.
- Operator section: `algorithm` (SHA1, SHA256 or SHA512, default SHA1), `digits` (6–8, default 6) and `period` (`30s` or `60s`, default `30s`), for new enrolments alone; `drift-steps` (0 or 1, default 1), for every factor's check.
- To `mfa`'s `factorKinds`: kind `totp`, amr `otp`, adding `mfa`, guessable and counting.
- `enroll`: a new secret, shown as base32 with an otpauth URI, the algorithm, digits and period.
- `verify`: valid with the step used as the next state, invalid, or replayed.

## Invariants
- A factor keeps the algorithm, digits and period it was enrolled with; moving it means enrolling again. Its secret is kept marked `<algorithm>:<digits>:<period>:` where they are not 0.19's; one unmarked is read with 0.19's, SHA-1, 6 digits and 30-second steps, whatever the section says. A mark that does not read is unavailable, never a verdict, and spends no attempt.
- Some authenticator apps make SHA-1, 6-digit, 30-second codes whatever the enrolment asks; the enrolment's first code then fails, and nothing is bound.
- On `kernel`'s clock, a code is accepted for the current step of the factor's period or `drift-steps` of them either side, and refused as invalid otherwise.
- Every step in that window is compared in constant time, so timing does not tell which one matched.
- A step at or before the last one used is refused as replayed, the same code or an older one.
- Replay protection rests on the state `mfa` keeps, which its store keeps through a crash and a failover; restoring the store from a backup brings used steps back.
- The secret is as many random bytes as its HMAC's output: 20 for SHA-1, 32 for SHA-256, 64 for SHA-512.
- The otpauth issuer and label prefix are the public origin's host, port included, or `auth` without a public origin.

## Depends on
- `kernel`, `http`, `mfa-extensions` (the kind's contract), `mfa` (composed for it: it stays among this package's dependencies, so adding this kind composes `mfa`)

## Vocabulary
- Step: one period of a factor's TOTP (30 or 60 seconds), counted from the Unix epoch.
