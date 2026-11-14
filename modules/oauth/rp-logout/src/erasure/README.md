# erasure

Internal module of `rp-logout`: erasing a subject's notice bodies, and draining the 0.19 notices into bodies once.

## Responsibilities
- The eraser `rp-logout`, contributed to `erasure-extensions`' `erasers`, as the bodies' space's `erasedBy` names it.
- The set of erasure ports the bodies offer, whole or not at all.

## Not here
- What the store keeps and how it fences (the Store). When erasure runs (`account-erasure`). A notice's body and its move (`notice-body`).

## Offers
- `noticesEraser` (the bodies, the queue, the 0.19 notices, a log, a clock) → the eraser: a subject's bodies erased through `erase`, a window doing the same for each subject, and `migrate`: the 0.19 notices drained, then the bodies' own migrate. It runs after no other eraser. `erasable` only where the bodies offer both ports, empty reports where not.
- `portsRefused` (the bodies) → why their ports cannot be used, or none: `erase` and `migrate`, both or neither, a part refused at build by the package's module; `portsOf` → both, or none.

## Invariants
- `logoutGaps` counts the distinct sessions among the bodies an erasure removes, each named in its body; one that does not read counts on its own, high. A session closing at erasure may be counted by both `session-lifecycle` and `rp-logout`, high too; a run cut short after a commit counts low.
- With no `after`, either order ends with the client told or the session counted: a late close comes from the follower or the closing sweep, not from `session-lifecycle`'s eraser, and its notices meet the subject's tombstone (`notices`' card).
- The drain moves each 0.19 notice to a body and an entry, then done; one past its time or unreadable is done and logged; one whose subject is erased is done, nothing kept. The migration answers `owner-stopped` only for work not finished (the store unavailable, an abort, a notice not moved, a full queue), and runs the bodies' own migrate even then, both answers returned.
- A body written before indexing is read for the subject it names, where it reads and hashes to its id; any other is unreadable, never an orphan.
- Each port is called on the bodies, so an implementation keeps its own `this`. The eraser's build takes only the stores, collecting no probes.

## Depends on
- `erasure-extensions` (`Eraser`, `ownerStopped`, the ports' types), `kernel` (`Log`, `Clock`); the package's store interfaces and `notice-body`.
