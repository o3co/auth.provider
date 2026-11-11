# erasure

Internal module of `subject-revocation`: marking a subject erased, the fence a bundle of credentials passes, and the boot gate.

## Responsibilities
- Writes a subject's mark of erasure, fences issuance against it, and keeps a composition that does not guard erasure from serving where it is enabled.

## Not here
- Reading the mark in a comparison, and refusing an erased subject: internal module `boundaries`. When a subject is erased: account erasure. Which bundles pass the fence: their issuers, through `tokens`.

## Offers
- `markedIn` (the store) → `markErased`: the mark, at the deadline of the write that makes it.
- `erasureMark` (the store) → the one reading of whether erasure is enabled: on or off once read, held for the process; unread while the store cannot answer, read again next time; cannot tell where the store has no reading, known without it. The gate, the probe and the fence read its state, never the store's ports. `fenceOver` (the store, that reading) → the fence; `receiptLifetimeMs`.
- The reading is a provision of its own, which the fence takes. The gate collects `erasers` and is taken by the probe alone, so no eraser's build may reach it, as one that collects `probes` does.

## Invariants
- The mark is the deadline of a confirmed write, on the store's clock; the boundaries stay as they are, and a subject marked already keeps its first mark, which is answered, its record left as it is, whatever else it holds. A mark of no time is never marked over: unavailable, as the read is. A mark of a time is read first, so the comparison and the fence answer it as marking does: revoked and erased.
- A subject with no boundary, or one of no time, gets a `sessions` boundary at the mark's time with it: a record holds `sessions`. A write the store answers with no mark is unavailable.
- The fence writes nothing where erasure reads off. Elsewhere, unread and cannot tell included (the closed side), it keeps a receipt `{ id }` where the subject's boundary holds no mark, held by the boundary as read; where it holds one, `erased`, nothing written. A receipt id already holding a receipt is thrown, never passed, whatever the boundary holds. A store that cannot fence is unavailable there, but where it cannot tell either: it passes, the exclusion below.
- A receipt lives a minute, fixed: nothing reads it, and a minute outlives its write's resends (records' 10-second deadline and a second).
- Covered (the store fences, a module contributes to `erasureGuards`, and every composed eraser is `erasable`) is known without the store: a covered composition starts and is ready whatever the store answers. One not covered reads the mark at start: enabled refuses the boot, naming the owners that cannot erase; unread starts it unready (probe `subject-revocation.erasure`) until the mark reads off.
- Each owner that cannot erase is warned at every start (`subject-revocation.erasure_unerasable`, with `owners`); 0.22 requires them.
- An unread mark never refuses the boot: a store's absence refuses none, or an erasure-off node would crash-loop on a store blip. A node not covered serves without fences or without every owner erasing, so wherever erasure is enabled, traffic must reach an instance only once it reports ready, from the first request, direct and internal traffic included: the server listens before it is ready.
- Where the store cannot tell whether erasure is enabled, start and readiness read it as off, with a warning at every start (`subject-revocation.erasure_unknown`, meaning cannot tell); a store that fences all the same fences every bundle in a guarded composition, as off cannot be known there.
- A store that can neither tell nor fence passes bundles unwritten, an unguarded composition (no guard, as where `subject-check` is `none`) fences no issuance there, and an owner that cannot erase keeps what it holds: the stated exclusion, each named in its warning with the rule "this node must never serve a deployment where erasure is enabled". 0.22 refuses them.
- The process reads the mark once: enabling erasure restarts every node.

## Depends on
- `kernel` (Unavailable, probes), `erasure-extensions` (`erasers`); internal module `boundaries`; `subject-revocation`'s contract and store interface.
