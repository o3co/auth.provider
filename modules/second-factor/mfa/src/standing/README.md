# standing

Internal module of `mfa`: whether a subject's counting factors stand.

## Responsibilities
- Answers whether a subject holds a counting factor at a login or a binding, as the witnessing tells it when one is composed and as the store does otherwise.
- Judges each counting factor of a unique value by its claim, and counts the ones that stand and the ones that do not.

## Not here
- Clearing the factors and the mark: `clearing`. Binding a factor: `binding`. What a counting factor is: `mfa-reading`'s contract.

## Offers
- `standingWith` (the shared parts) → `standing`, `standingIds`, `countsNow`, `writtenStanding`, `unclaimedWritten`.

## Invariants
- A counting factor of a unique value stands while its claim names it; one written before claims were kept stands unless another holds its value; one whose claim is missing does not.

## Depends on
- `mfa-extensions` (`Asked`); `mfa`'s records and shared parts.
