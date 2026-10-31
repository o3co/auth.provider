# standing

Internal module of `tokens`: a token's standing time, as its claim writes and reads it.

## Responsibilities
- Writes a grant's standing time as the token's `o3co_standing_at`, and reads a token's standing back from that claim or its `iat`.

## Not here
- Signing and parsing the token, and refusing it as `shape` (the package's verification). Comparing the standing with the subject's boundary (the subject check, contributed by `subject-tokens`).

## Offers
- `standingOf` (a grant, the token's `iat` in seconds) → the claim's value: the standing time in whole seconds, floored and never after `iat`; none where the grant gives none. A standing time that is no number is the caller's mistake (RangeError).
- `standingRead` (the claim, `iat`) → the token's standing in seconds, the claim else `iat`; none for a claim after `iat`, which tokens never writes.

## Invariants
- The standing never moves a token's lifetime: `iat` and `exp` are computed without it.
- A standing before the epoch, as a grant with no time of its own gives, is kept as it is.

## Depends on
- None; the package's grant type.
