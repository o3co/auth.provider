# mfa-recovery

## Responsibilities
- Contributes recovery codes to `mfa` as a second-factor kind.

## Not here
- When codes are issued or reissued, and what is audited (`mfa`).
- Sealing the set, storing it, and keeping two uses of one code from both winning (`mfa`).
- Showing the codes to the user (`mfa-flows`).

## Offers
- Composition definition only.
- Factor kind `recovery_code`: amr `recovery`, adds `mfa`, not guessable, does not count.

## Invariants
- A set is 10 codes of 80 random bits each, written `XXXX-XXXX-XXXX-XXXX` in Crockford's base32.
- A new set is made whatever the subject already holds.
- The secret keeps only SHA-256 digests of the codes, never the codes.
- A code is read whatever its case and hyphens.
- Each code works once, and a use tells how many are left; a code used before is `replayed`, and one not in the set is `invalid`.
- The factor's state is the digests used so far, so the kind holds nothing between calls.

## Depends on
- `kernel`, `mfa`

## Vocabulary
- Recovery code: a one-time code from a set, for when the user loses their other factors.
