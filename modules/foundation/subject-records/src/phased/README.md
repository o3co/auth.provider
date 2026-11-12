# phased

Internal module of `subject-records`: the builders over the phase a process holds, so a store's blip at start refuses no start.

## Responsibilities
- Builds `subjectRecordsIn`, `subjectKeyedSetsIn` and `jointRecordsIn`, and a space's erasure and migration, once the phase reads, and tells readiness whether it has.

## Not here
- Reading the phase once: internal module `phase` (`once`). What each phase writes: the builders. The probe: the template's, one line over `ready`.

## Offers
- `phasedRecordsIn` and `phasedKeyedSetsIn` (a place with no phase, the phase read once, where, the builder's `refuse`, as the builders take them) → the builder's methods, each answering through that phase, and `ready`, the template's probe check.
- Each also answers the space's `erase` (a subject, a signal, for records `eachRemoved` too) and `migrate` at that phase: `phasedRecordsIn`'s a walk, the owner's `SubjectReading`, a signal and optionally its `Elsewhere`; `phasedKeyedSetsIn`'s a walk, the owner's `SetReading` and a signal. They come in the order an owner's store ports take them, so the wiring maps them with no arrow and never handles the phase. `unowned`'s `closed` answers that phase as captured, not the mark at the write.
- `phasedJointRecordsIn` (places by name, with no phase; the phase read once; where; `refuse`) → `changeSubjectRecords` and `ready`. Given the template's one `PhaseOnce`, its builders and the joint change see one phase. It has no `erase` or `migrate`: each place's builder has them.

## Invariants
- Where the phase reads at build, the builder is built at once and refuses as it does, refusing the start.
- Where it cannot, the build waits for the first call that reads it; until then every call is unavailable and `ready` fails, so ready traffic never reaches them.
- A refusal found then (indexed over a store with no batch across, an index not the space's, another category) keeps `ready` failing with its reason for good, logs `subject-records.refused` once for each space it names, and leaves every call unavailable: it fails readiness, never a call's judgment.
- A process may hold `reader` for one space and `indexed` for another where the mark is written between their reads; every node restarts after the mark (account erasure §5.1).

## Depends on
- `kernel` (Unavailable), `store`, `erasure-extensions` (`Walk`, `SubjectReading`, `Elsewhere`); internal modules `phase`, `sets`, `erase`, `migrate`, `joint`, and the package's `subjectRecordsIn`
