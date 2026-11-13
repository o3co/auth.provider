# erasure

Internal module of `code-grant`: erasing a subject's codes and redemption records.

## Responsibilities
- The eraser `code-grant`, contributed to `erasure-extensions`' `erasers`, as both its places' spaces' `erasedBy` name it.

## Not here
- What the places keep and how they fence (the Store). When erasure runs (`account-erasure`).

## Offers
- `codeGrantEraser` (the code store, the redemption records) → the eraser: a subject's codes and redemption records fenced through each place's `erase`, a window doing the same for each subject, and `migrate` on each reading none (both are bounded); `erasable` only where both places offer both ports, empty reports where not.
- `portsRefused` (the places) → why their ports cannot be used, or none: `erase` and `migrate` of both come all four or none, a part refused at build in the grant's factory; `portsOf` → the set, whole, or none.

## Invariants
- A migration asked to read a code or redemption record throws: a bounded record is never indexed.
- Each port is called on its place, so an implementation keeps its own `this`.
- The eraser's build takes only the places, collecting no probes: the erasure gate collects erasers.

## Depends on
- `erasure-extensions` (`Eraser`, the reports); the package's store interfaces.
