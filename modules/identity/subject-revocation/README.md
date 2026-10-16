# subject-revocation

## Responsibilities
- Records two revocation boundaries per subject, `sessions` and `delegations`, and lets others compare against them.

## Not here
- Deciding what to revoke (the reader compares), and the work that follows a revocation (its followers').

## Offers
- `revocations.record(subject, { keepDelegations? })`: moves `sessions` to the present time on `kernel`'s clock, and `delegations` too unless kept, then answers `{ complete }`: whether every follower finished all its work, none left for later.
- `revocations.compare(subject, time, kind, allowanceMs?)`: valid, or revoked by that kind's boundary widened by the allowance (none by default).
- `subjectRevocation`: `revoke(subject)` records both kinds; `check(subject, authenticatedAt)` compares with `sessions`, the time in epoch milliseconds.
- Extension point `revocationFollowers`: `follow(subject, { keepDelegations })`, called after each `record` has written the boundary, one at a time in collect order; a follower that leaves any of its work for later fails. Each must be safe to call again and to run from several hosts at once: concurrent revocations and a repeated `record` both call it again.
- Store interface for boundaries (per subject: save unless held / read / write from what it holds, kept without end), and what it needs from a store (never evicted, survives a crash, does not come back on failover).
- The store needs no confirmed reads: the state is on the refusing side, and each `record` is reported only after its confirmed write.
- `./testing`: contract tests of both revocation interfaces and of the store interface, for every implementation, and a stand-in of both interfaces keeping boundaries in memory on the composition's clock by the same rules, which the contract test runs on too.

## Invariants
- A kept `delegations` boundary stays where it was; a subject has none until a revocation moves it.
- The boundary only moves forward, on `kernel`'s clock, and recording is reported only when the confirmed write returns (how it is written: internal module `boundaries`).
- Each `record` writes the boundary, even one already far enough, so a write not yet confirmed is confirmed by the next.
- The boundary is placed by the revoking host's clock; a clock running ahead refuses new logins until that time, and no interface moves it back. Keeping clocks right is the operator's job.
- A failing follower is logged by name and kind and does not stop the rest; the boundary stays, nothing here retries it, and `record` answers incomplete.
- Comparison is in seconds; what started up to the second of the boundary plus the allowance is revoked. An allowance below zero is none, and one that is no number revokes. Comparison is done only through the offered interface and is not reimplemented by callers.
- When it cannot be read, it is unavailable, not "no boundary". A record that holds no time is unavailable too, and a revocation over it moves both kinds.

## Data
- One record per subject: `sessions`, and `delegations` once a revocation moved it.
- A record of a single time is read as that time for both boundaries.

## Depends on
- `kernel`

## Vocabulary
- boundary: the time at or before which what started is invalid. `sessions` covers authentications; `delegations` covers upstream credentials held for clients.
- follower: a contribution that does closing work once a revocation is recorded, such as telling others; the boundary alone already refuses what it covers.

## Rules for callers
- Record `complete: false` in the audit. The operator converges by calling `record` again; that moves the boundary to the present time, so it only refuses more.
