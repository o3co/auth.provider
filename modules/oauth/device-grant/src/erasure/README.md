# erasure

Internal module of `device-grant`: erasing a subject's approvals, and checking the devices for any 0.19 approval kept on them.

## Responsibilities
- The set of erasure ports the stores offer, whole or not at all.

## Not here
- What the stores keep and how they fence (the Store). When erasure runs (`account-erasure`).

## Offers
- `portsRefused` (the device store, the approvals) → why their ports cannot be used, or none: the approvals' `erase` and `migrate` and the devices' `walk` come all three or none, a part to be refused at build; `portsOf` → the set, whole, or none. Nothing takes them yet.

## Invariants
- Each port is called on its place, so an implementation keeps its own `this`.

## Depends on
- `erasure-extensions` (the ports' types); the package's store interfaces.
