# witness

Internal module of `mfa`: how mfa asks the enrollment witness, and how a first binding marks it.

## Responsibilities
- Judges a subject's standing from its counting factors and the witness, and asks the witness to mark a first binding by its token.

## Not here
- The witness's contract and promises: `mfa-witness`. When mfa marks, re-reads and clears: `mfa`'s factor decisions.

## Offers
- `standingOf` (witness, audit, log) → (subject, whether it holds a counting factor, where it is judged) → `held` or `none`; a mark beside no counting factor records `mfa.enrollment_inconsistent` with `at`, logs a warning and is unavailable, as is a witness that cannot be read.
- `markedBy` (witness, subject, token): whether the mark is the token's, asking again while the witness is unavailable.
- `settlingOf` (witness, whether the subject holds a counting factor, new tokens) → (subject): after a write, a counting factor with no mark is marked under a new token; a mark with nothing counting is cleared only where this call set it (a reset took the factor meanwhile), as any other may be a store that lost its factors. It reads again after each change, settles twice at most, and is unavailable while they still differ.

## Invariants
- A subject holding a counting factor is `held` without asking the witness.
- `markedBy` asks again three times with the same token, which answers alike, before it fails as unavailable.
- A binding marks only after its factor is written, so the mark always follows a factor; a first binding meeting a mark with nothing counting is a store that lost its factors, and is unavailable before it writes. A pending binding's token, sealed by earlier versions, is no longer read.

## Depends on
- `mfa-witness` (its contract), `audit`, `kernel`
