# erasure

Internal module of `code-grant`: erasing a subject's codes and redemption records.

## Responsibilities
- The erasure ports of code-grant's two places, as one set.

## Not here
- What the places keep and how they fence (the Store). When erasure runs (`account-erasure`).

## Offers
- `portsRefused` (the places) → why their ports cannot be used, or none: `erase` and `migrate` of both come all four or none, a part refused at build in the grant's factory; `portsOf` → the set, whole, or none.

## Invariants
- Each port is called on its place, so an implementation keeps its own `this`.

## Depends on
- `erasure-extensions` (the reports); the package's store interfaces.
