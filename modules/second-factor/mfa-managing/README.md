# mfa-managing

## Responsibilities
- Owns the contract for managing a subject's second factors: naming and removing them, removing them all, the recovery codes, and the subject's fence.

## Not here
- The records, and the decisions made over them: `mfa`, which provides the contract. Binding a factor: `mfa-binding`. What a counting factor is, and `Fence`: `mfa-reading`. An operator's reset, its sessions and lockout: `mfa-reset`.

## Offers
- `factorManaging` (`mfa.factor-managing`), provided by `mfa`: `rename`; `remove`; `clear` (every factor of the subject, of any kind → how many, and their kinds sorted once each); `reissue` (the first set too; `full` past `max-factors`); `fence` (no binding begun before binds); `fenceOf`.
- `Reissued`.

## Invariants
- `remove` and `reissue`, given a fence read before (`fenceOf`'s, or a binding's), change nothing (`fenced`) once it moved past it. The fence stops `bind`, `remove` and `reissue` only: `rename` and `prove` do not read it.
- "required" never removes the last counting factor (`last`); a factor of a unique value not yet claimed does not count as one.
- Removing the last counting factor removes the recovery codes in the same write. Recovery codes are written by `reissue` alone, handed once in that call, and count toward `max-factors`.
- A way back that will not enrol fails `reissue` as unavailable.
- `rename` refuses a label not of its shape (`malformed-label`) before anything is read.
- With a witnessing, the last counting factor is never removed. `clear` removes the factors, then has the mark go, giving the witnessing `after` (`mfa-extensions`' `AfterReset`), which judges the fence against the reset's own before what stands.

## Depends on
- `kernel`, `mfa-reading` (`Fence`)
