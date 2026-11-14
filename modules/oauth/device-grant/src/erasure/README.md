# erasure

Internal module of `device-grant`: erasing a subject's approvals, and checking the devices for any 0.19 approval kept on them.

## Responsibilities
- The eraser `device-grant`, contributed to `erasure-extensions`' `erasers`, as the approvals' space's `erasedBy` names it.
- The set of erasure ports the stores offer, whole or not at all.

## Not here
- What the stores keep and how they fence (the Store). When erasure runs (`account-erasure`). The walk of the devices (the Store, through `walk`).

## Offers
- `deviceGrantEraser` (the device store, the approvals) → the eraser: a subject's approvals fenced through `erase`, a window doing the same for each subject, and `migrate`: the approvals' own, reading none (they are bounded), then the devices checked through `walk`. It runs after no other eraser. `erasable` only where the stores offer the set whole, empty reports where not.
- `portsRefused` (the device store, the approvals) → why their ports cannot be used, or none: the approvals' `erase` and `migrate` and the devices' `walk` come all three or none, a part refused at build by the package's module, which requires the approvals; `portsOf` → the set, whole, or none.

## Invariants
- The devices hold no subject from 0.20, but a 0.19 approval stays on its record, as 0.20 never removes one. The migration answers `owner-stopped` (the owner's stop for a part subject-records does not read) while any device record holds one, for a record it cannot open, as one that may hold a subject, and for a walk that did not finish, never read as clean. The check, and the devices' `walk`, go at 0.22 with the 0.19 approval read; the approvals' `erase` and `migrate` are required then.
- The stop's reason gives one bound, frozen from v0.19.1: 7,200 s after the last 0.19 instance stopped, as 0.19 keeps a device's record twice `code-lifetime`'s longest, 3600 s; and that a stop past it means a 0.19 instance is still writing.
- A migration asked to read an approval throws: a bounded record is never indexed.
- Each port is called on its place, so an implementation keeps its own `this`.
- The eraser's build takes only the stores, collecting no probes: the erasure gate collects erasers.

## Depends on
- `erasure-extensions` (`Eraser`, `ownerStopped`, the ports' types); the package's record and store interfaces.
