# witness

Internal module of `mfa`: how mfa asks the enrollment witness, and how a first binding marks it.

## Responsibilities
- Judges a subject's standing from its counting factors and the witness, and asks the witness to mark a first binding by its token.

## Not here
- The witness's contract and promises: `mfa-witness`. When mfa marks, re-reads and clears: `mfa`'s factor decisions.

## Offers
- `standingOf` (witness, audit, log) → (subject, whether it holds a counting factor, where it is judged) → `held` or `none`; a mark beside no counting factor records `mfa.enrollment_inconsistent` with `at`, logs a warning and is unavailable, as is a witness that cannot be read.
- `markedBy` (witness, subject, token): whether the mark is the token's, asking again while the witness is unavailable.

## Invariants
- A subject holding a counting factor is `held` without asking the witness.
- `markedBy` asks again three times with the same token, which answers alike, before it fails as unavailable.
- A first pending binding holds a token of 16 random bytes, sealed with it, never shown or logged; a first pending binding holding none is refused under a witness.
- After a first binding writes, mfa reads the mark again: gone, a reset cleared it, so the binding takes back what it wrote (once more where the store cannot answer the first time) and is refused with `reason` `reset-cleared`; another binding's mark refuses it with `competing`.

## Depends on
- `mfa-witness` (its contract), `audit`, `kernel`
