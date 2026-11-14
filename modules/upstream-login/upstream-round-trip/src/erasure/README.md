# erasure

Internal module of `upstream-round-trip`: checking, once, that no round trip a 0.19 instance began, which may hold a subject, remains. TODO(0.22): goes with the legacy reading.

## Responsibilities
- The eraser `upstream-round-trip`, contributed to `erasure-extensions`' `erasers`.

## Not here
- What a caller carries, and whose it is (each caller's). When erasure runs (`account-erasure`). The walk of the round trips (the Store, through `walk`).

## Offers
- `roundTripEraser` (the store) → the eraser: `online` and `window` erase nothing, the space holding no subject's data; `migrate` walks the round trips without opening one. It runs after no other eraser. `erasable` only where the store offers `walk`.

## Invariants
- The migration answers `owner-stopped` on the first round trip the walk meets, as a 0.19 link's may hold a subject and its content is the caller's; the reason gives one bound, the callers' longest lifetime, and that a stop past it means something still begins round trips. During the lockout no round trip begins, so the space empties within that bound.
- A walk that did not finish (`walk-unsteady`, `unavailable`) answers `owner-stopped`, never read as clean. It reports no space, so a run cut short throws the signal's reason, `online` and `window` included.
- The walk's reads need no confirmation: a round trip lost in a failover only starts again.
- The port is called on its place, so an implementation keeps its own `this`.

## Depends on
- `erasure-extensions` (`Eraser`, `ownerStopped`, the walk's type); the package's store interface.
