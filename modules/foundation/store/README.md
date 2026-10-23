# store

## Responsibilities
- Owns the contract of feature-neutral storage operations, each atomic and judged on the store clock, collects space declarations, and holds one memory implementation, not safe on many instances.

## Not here
- What values mean, their shapes and rules; feature vocabulary; connections to outside infrastructure.

## Offers
- The `store` contract: reads of one key, answering value, version and the store clock's time; and a scan of a space's live value keys by pages, which lists each key living through the walk unless a failover or restart falls in it (a later walk lists it).
- Writes: if absent, on a version, remove on a version or a value, take once, a batch in one partition under conditions, and `mutate`, whose pure function runs again on each retry.
  - `batchAcross`, where a store offers it: a batch over keys of any partition, and of any spaces declaring the same guarantees. A store without it leaves it out.
- Expiry after a duration, at a time, none, keep, or extend only; counting in a fixed window.
- The space declaration extension point, and the composition definition with `accept-volatile` (default false), which lets spaces needing durable or replicated boot on memory.
- `./testing`: the contract test, test configuration builders, and a simulated replicated store that loses what a space's missing guarantees allow (unconfirmed writes on failover, writes not durable on restart, entries not kept from eviction under memory pressure).

## Invariants
- Declared `forWiring`: a feature's storage is built on this by its wiring, so no feature depends on it; a feature's tests take it through `./testing` alone.
- Versions are opaque, compared only for equality, and never repeat for a key, even after a delete or a failure (for memory, within the process).
- A value lives only while the store clock is before its expiry; at the expiry, reads and writes both see it expired.
- Failures are unavailable, apart from absent and conflict; only declared spaces are accepted, with the guarantees they declare.
- Input is copied once at the boundary and checked: plain JSON only (no accessors, classes, `__proto__` or hidden properties; -0 is 0), well-formed strings, integers in range.
- A batch is checked whole before anything is written, never writes a key twice, and never reaches outside its partition. A batch across is checked the same, and refuses spaces of other guarantees, so a fault keeps or drops it whole.
- An idempotency mark binds the partition and the request: a resend gets the first answer, refusals included, and another request is refused as reused.
  - A batch across keeps its mark, with one answer and one end, in every partition it touches, those it only reads included, and looks for it in all of them first: a resend meets it in any, another request meeting it in any is reused (its keys' order is part of the request), and a late answer is not kept.
- A write past its deadline is refused as late; a mark is forgotten 1 second past the deadline, or 5 minutes 1 second after the write without one.
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
