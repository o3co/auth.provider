# phased

Internal module of `subject-records`: the builders over the phase a process holds, so a store's blip at start refuses no start.

## Responsibilities
- Builds `subjectRecordsIn` and `subjectKeyedSetsIn` once the phase reads, and tells readiness whether it has.

## Not here
- Reading and holding the phase: internal module `phase` (`held`). What each phase writes: the builders. The probe: the template's, one line over `ready`.

## Offers
- `phasedRecordsIn` and `phasedKeyedSetsIn` (a place with no phase, the held phase, where, the builder's `refuse`, as the builders take them) → the builder's methods, each answering through the held phase, and `ready`, the template's probe check.

## Invariants
- Where the phase reads at build, the builder is built at once and refuses as it does, refusing the start.
- Where it cannot, the build waits for the first call that reads it; until then every call is unavailable and `ready` fails, so ready traffic never reaches them.
- A refusal found then (indexed over a store with no batch across, an index not the space's, another category) keeps `ready` failing with its reason for good, logs `subject-records.refused` once, and leaves every call unavailable: it fails readiness, never a call's judgment.
- A process may hold `reader` for one space and `indexed` for another where the mark is written between their reads; every node restarts after the mark (account erasure §5.1, step 6).

## Depends on
- `kernel` (Unavailable), `store`; internal modules `phase`, `sets`, and the package's `subjectRecordsIn`
