# account-erasure

## Responsibilities
- The feature account erasure runs as: its commands (internal module `commands`), each one under the maintenance key run in one frame (internal module `frame`).
- Declares erasure's own maintenance interface, which its wiring alone provides (internal module `maintenance`), and the one step a command under the maintenance key runs (internal module `step`).

## Not here
- What a subject's data is in each module and how it is erased: that module's eraser (`erasure-extensions`). The erasure journal: `erasure-journal` and its adapter.
- The store's maintenance key, control record and ledger: `store`, reached only through the maintenance interface, as its wiring (`account-erasure-store`) maps them.

## Offers
- Composition definition only, opt in: the full template composes it only where it is added.
- `erasureMaintenance`, on `.`: the maintenance interface, declared here for account-erasure alone to take (`takenBy`), provided by its wiring.
- `erasureCommands`, on `.`: the erasure commands, each called by its app entry (`appEntries`): `erasure-enter`.

## Invariants
- Its module takes `erasureMaintenance` and `erasureJournal`: composed without its wiring, or without a journal adapter, it refuses the boot.
- It never depends on `store`. The wiring maps store's contracts and subject-records' phase onto the maintenance interface, each side's words its own.
- The check of `alone` catches provider processes of any version still attached after the operator's store cut-off. It does not prove that nobody else can touch the data.
  - `alone` holds at the moment asked: the store does not stop a later attach; the store cut-off does.
  - Every provider is counted: one that cannot run the store's commands on the data is refused at boot.

## Depends on
- `kernel`, `erasure-journal`

## Vocabulary
- alone: no other process is attached to the store's data, as the store saw it when asked.
- accompanied {count}: other processes are attached; the count is the store's, for the operator to read.
- unchecked {reasons}: the store could not see every process that may be attached; the reasons are codes for the operator.
- busy: the journal is held, by another erasure command or by a hold one left behind; its holder, as the medium records it, is for the operator.
- hold-left {answer}: the command reached its answer, which stands, and its hold's release then failed (unavailable): the hold may stay, and the next command answers `busy` until the operator releases it.
- not-in-maintenance: the maintenance key is not held, or is held with no epoch.
- entry time: when `erasure-enter`, having entered the present epoch, was shown alone; kept as the mark `account-erasure.entered`.
- entered-not-shown-alone: `erasure-enter` set the key and was then not shown alone: the store answered `accompanied` or `unchecked`, or gave no answer (`unavailable`).
