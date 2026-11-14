# erasure

Internal module of `upstream-round-trip`: checking, once, that no 0.19 round trip (the package's Vocabulary) remains. TODO(0.22): goes with the 0.19 round trips.

## Responsibilities
- The eraser `upstream-round-trip`, contributed to `erasure-extensions`' `erasers`.

## Not here
- What a caller carries, and whose it is (each caller's). When erasure runs (`account-erasure`). The walk of the round trips (the Store, through `walk`).

## Offers
- `roundTripEraser` (the store) → the eraser: `online` and `window` erase nothing, the space holding no subject's data; `migrate` walks the round trips without opening one. It runs after no other eraser. `erasable` only where the store offers `walk`.

## Invariants
- The migration answers `owner-stopped` on the first round trip record the walk meets, as a 0.19 round trip may carry a subject's data and what it carries is the caller's. The reason says when to run again: once the longest lifetime the deployment's callers give has passed since the lockout (at most 3,600 s for 0.19.1's own callers), and that a stop past that means something still begins round trips. During the lockout no round trip begins, so the space empties within that time.
- A walk that met no record when an abort comes after its last page answers `walked`: it finished (records' `walk` card), so the migration answers none.
- A walk that did not finish (`walk-unsteady`, `unavailable`) answers `owner-stopped`, never read as clean. It reports no space, so a run cut short throws the signal's reason, `online` and `window` included.
- The walk's reads need no confirmation: a round trip lost in a failover only starts again.
- The port is called on its place, so an implementation keeps its own `this`.

## Depends on
- `erasure-extensions` (`Eraser`, `ownerStopped`, the walk's type); the package's store interface.
