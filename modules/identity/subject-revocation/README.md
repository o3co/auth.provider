# subject-revocation

## Responsibilities
- Records two revocation boundaries per subject, `sessions` and `delegations`, and lets others compare against them.

## Not here
- Deciding what to revoke (the reader compares), and the work that follows a revocation (its followers').

## Offers
- `revocations.record(subject, { keepDelegations? })`: moves `sessions` to the deadline of the write that records it, and `delegations` too unless kept, then answers `{ complete, erased? }`: whether every follower finished all its work, none left for later, and `erased` where the record its committed write read carried a mark of erasure, absent otherwise.
- `revocations.compare(subject, time, kind, allowanceMs?)`: valid, or revoked by that kind's boundary widened by the allowance (none by default).
- `subjectRevocation`: `revoke(subject)` records both kinds; `check(subject, authenticatedAt)` compares with `sessions`, the time in epoch milliseconds.
- Erasure (internal module `erasure`): `subjectErasure.markErased(subject)`, the mark for good, taken by no module until account erasure is named; `erasureFence.fence(subject, receiptId)`, passed or `erased`, one per bundle of credentials; `erasedSubjects.erased(subject)`, marked or not, read each call, for a module neither calling nor following `record`, no access check; extension point `erasureGuards` (many), a module's statement that it checks and fences on this boundary; the boot gate.
- Extension point `revocationFollowers`: `follow(subject, { keepDelegations, erased? })`, `erased` as `record` answers it (see the rules for callers), called after each `record` has written the boundary, one at a time in collect order; a follower that leaves any of its work for later fails. Each must be safe to call again and to run from several hosts at once: concurrent revocations and a repeated `record` both call it again.
- Store interface for boundaries (per subject: save unless held / read / write from what it holds, kept without end, each write handing its deadline; optional `fence` and `erasureEnabled`, the latter required in 0.22; `fenceWhere` gives a `fence` only where the store can fence), and what it needs from a store (never evicted, survives a crash, does not come back on failover).
- The store needs no confirmed reads: the state is on the refusing side, and each `record` is reported only after its confirmed write.
- `./testing`: contract tests of both revocation interfaces and of the store interface (its fence and mark where it has them), for every implementation, a stand-in of both interfaces keeping boundaries in memory on the composition's clock by the same rules, marking a subject erased (`subjectErasure`) too, a boundary at the time it is recorded, as no write waits, and one whose reads can lag behind its records (`laggingRevocation`), which the contract test runs on too.

## Invariants
- A kept `delegations` boundary stays where it was; a subject has none until a revocation moves it. Each `record` writes the boundary, even one already far enough, so a write not yet confirmed is confirmed by the next.
- The boundary only moves forward, and recording is reported only when the confirmed write returns; a write that lands past its deadline is unavailable (how it is written: internal module `boundaries`).
- The boundary is the deadline of the write that recorded it, on the store's clock, so it is never earlier than the time the write became visible; a login within the store's write patience after a revocation (10 s) is refused, up to about 11 s with second rounding.
- A boundary is compared with times from the hosts' clocks, so the store's clock joins them: a host ahead of the store by d leaves d of a window, one behind refuses d more, and no interface moves a boundary back. Keeping clocks right is the operator's job.
- A failing follower is logged by name and kind and does not stop the rest; the boundary stays, nothing here retries it, and `record` answers incomplete.
- Comparison is in seconds; what started up to the second of the boundary plus the allowance is revoked. An allowance below zero is none, and one that is no number revokes. Comparison is done only through the offered interface and is not reimplemented by callers.
- An erased subject is revoked by every comparison, whatever the time, kind or allowance; the mark is never moved or dropped. Where erasure is enabled and the mark is read, a composition not covered does not start, naming the owners that cannot erase; unread, it starts unready, and traffic must reach only ready instances; a store that cannot tell is the stated exclusion. A covered one starts whatever the store answers.
- When it cannot be read, it is unavailable, not "no boundary". A record that holds no time is unavailable too, and a revocation over it moves both kinds. A record with a mark of erasure that is a time is revoked, and fenced as erased, whatever else it holds.

## Data
- One record per subject: `sessions`, and `delegations` once a revocation moved it; a record of a single time is read as that time for both.

## Deprecated
- A `BoundaryStore` without `erasureEnabled`: warned at every start (`subject-revocation.erasure_unknown`), and where it fences, every bundle of a guarded composition is fenced (+1 write) until it tells; 0.22 refuses it.

## Depends on
- `kernel`, `erasure-extensions` (the erasers the gate reads `erasable` of)

## Vocabulary
- boundary: the time at or before which what started is invalid. `sessions` covers authentications; `delegations` covers upstream credentials held for clients.
- follower: a contribution that does closing work once a revocation is recorded, such as telling others; the boundary alone already refuses what it covers. covered: the store fences, a module guards erasure (`erasureGuards`), and every composed eraser is `erasable`.

## Rules for callers
- Record `complete: false` in the audit. Whoever is told `erased`, by `record`'s answer or by `follow`'s argument, writes no audit record naming the subject and creates no record under it; changing or removing what is there stays allowed. The operator converges by calling `record` again; that moves the boundary to its write's deadline, so it only refuses more.
- An artifact made from a check is stamped with a time taken before the check's read, or the proof is compared again by a read after the stamp; either way one made while a boundary's write was in flight is refused once it lands.
