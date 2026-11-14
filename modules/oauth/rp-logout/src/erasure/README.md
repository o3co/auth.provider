# erasure

Internal module of `rp-logout`: erasing a subject's notice bodies.

## Responsibilities
- The set of erasure ports the bodies offer, whole or not at all.

## Not here
- What the store keeps and how it fences (the Store). When erasure runs (`account-erasure`).

## Offers
- `portsRefused` (the bodies) → why their ports cannot be used, or none: `erase` and `migrate`, both or neither; `portsOf` → both, or none. Nothing takes them yet.

## Invariants
- Each port is called on the bodies, so an implementation keeps its own `this`.

## Depends on
- `erasure-extensions` (the ports' types); the package's store interfaces.
