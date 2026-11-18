# store

## Responsibilities
- Owns the contract of feature-neutral storage operations, each atomic and judged on the store clock, collects space declarations, and holds one memory implementation (internal module `memory`).

## Not here
- What values mean, their shapes and rules; feature vocabulary; connections to outside infrastructure.

## Offers
- The `store` contract: reads of one key, answering value, version and the store clock's time; and a scan of a space's live value keys by pages, which lists each key living through the walk unless a failover or restart falls in it (a later walk lists it); `getMany`, reads of several keys, where a store offers it.
- Writes: if absent, on a version, remove on a version or a value, take once, a batch in one partition under conditions, and `mutate`, whose pure function runs again on each retry, 8 times where the caller names no count (a fixed margin against contention). A batch's answer tells the time it committed (`at`) where the store tells it.
  - `batchAcross`, where a store offers it: a batch over keys of any partition, and of any spaces declaring the same guarantees. A store without it leaves it out. Both take the subject writer as `writer`: once the options are checked whole, it is checked by its identity (another value, a copy among them, is a `TypeError`), and the store below is handed none of it.
- `storeControl` (reading), for wirings alone to take; `storeUpkeep` (keeping the data whole), taken by no module (`takenBy: []`): the control record, the ledger of spaces, `honours` and `sweep` (internal module `upkeep`).
- `./subject-writer`: the `subjectWriter` value (internal module `writer`; its type `SubjectWriter` is on `.`), kept by the manifest's `takenBy` for `subject-records` alone. It is published as `subject-records` loads it at run time, is no part of store's semver surface for anyone else, and changes with `subject-records` in the same release.
- A declaration's erasure fields (`subjectData`, `erasedBy`, `boundedMs`, `requiredOnceErasing`): erasure's words, carried for erasure to read and checked for their shape; every declaration names a `subjectData`, and one naming none refuses the boot, naming the space. store reads `subjectData` as `none` or not (`noSubjectData`) for its ledger, and asks the subject writer of a change to a space of the four categories `checks` names (`WriterHeld`).
- Expiry after a duration, at a time, none, keep, or extend only; counting in a fixed window.
- `codePointOrder`: the order of members and of ties, by code point, which is also the order of their UTF-8 bytes, the same for every store.
- The space declaration extension point, and the composition definition with `accept-volatile` (default false), which lets spaces needing durable or replicated boot on memory; every start that boots such spaces so warns `store.volatile_accepted`, naming them.
- `./testing`: the contract test (`storeContract`, in the internal modules `contract-harness`, `contract-keys`, `contract-marks`, `contract-batches`, `contract-walking`, `contract-writer` and `contract-faults`), test configuration builders, a simulated replicated store (internal module `simulated`), and a value written carrying the subject writer (`plantValue`, internal module `planting`).

## Invariants
- Declared `forWiring`: a feature's storage is built on this by its wiring, so no feature depends on it; a feature's tests take it through `./testing` alone.
- Versions are opaque, compared only for equality, and never repeat for a key, even after a delete or a failure (for memory, within the process).
- A value lives only while the store clock is before its expiry; at the expiry, reads and writes both see it expired.
- Failures are unavailable, apart from absent and conflict; only declared spaces are accepted, with the guarantees they declare.
- Every implementation is held to the contract by `checkedStore` (internal module `checks`): its input copied once and checked whole, and a change to a space of the four categories `checks` names refused as a `TypeError` unless it carries the subject writer.
- An idempotency mark binds the partition and the request: a resend gets the first answer, refusals included, and another request is refused as reused. Every implementation keeps a mark for `idempotencyWindows` and forgets it then: until a second past its deadline, or five minutes and a second after the write without one, fixed as the contract every store keeps alike.
  - A batch across keeps its mark, with one answer and one end, in every partition it touches, those it only reads included, and looks for it in all of them first: a resend meets it in any, another request meeting it in any is reused (its keys' order is part of the request), and a late answer is not kept.
- In a replicated space, a written answer confirms every state the store held before it; exists, conflict, missing, limited, `mutate`'s keep and a later unavailable write confirm nothing.
- In a space with confirmed reads, reads and refusing answers are confirmed before they return.
- No basic operation is added for one feature's convenience; one that seems needed is reported, not added.

## Rules for callers
- Unavailable means "may have been applied": settle it by resending with the same mark and a deadline. Compare values with `canonicalJson`.
- To allow on reading allow-direction state another request wrote, declare confirmed reads, unless that state is unused when the writer's confirmation fails, or the allow acts outside only after a later confirmed write.
- Replicated protects against failover only: declare durable too where a loss turns a deny into an allow; while replicas lag, writes and counting are unavailable, so deny; on failover, the store clock is another host's.

## Depends on
- `kernel`

## Vocabulary
- space: a key namespace a user declares. partition: the keys a batch and a consistent read reach. version: an opaque value that changes on every write. store clock: the storing side's time. deadline: past it, a write is refused as late. idempotency mark: a resend under it gets the same answer.
- guarantee: a property a space requires: no eviction (never dropped for room), durable (confirmed writes survive a crash), replicated (they survive a failover), confirmed reads.
