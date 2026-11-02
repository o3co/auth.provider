# clearing

Internal module of `mfa`: a reset's clearing of a subject's factors and its mark, and a first binding refused.

## Responsibilities
- Clears every factor of a subject in one write that moves its fence, then tells the witnessing what stands after it.
- Settles the witnessing's mark after a binding, and records a first binding refused with why.

## Not here
- Whether factors stand: `standing`. Binding: `binding`. How a witnessing judges and is settled: `mfa-extensions`' contract.

## Offers
- `clearingWith` (the shared parts, `standing`) → `settle`, `closed`, `clear`.

## Invariants
- Factors go first, then the mark: a failure between leaves a mark and no factor, which stops logins.
- What stands after a reset is read before the fence, and a fence behind the one the reset moved answers `unsure`.

## Depends on
- `mfa-extensions` (`AfterReset`); `standing`; `mfa`'s records and shared parts.
