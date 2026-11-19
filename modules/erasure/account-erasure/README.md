# account-erasure

## Responsibilities
- The feature account erasure runs as. Its module takes nothing and provides nothing yet: the contract it declares is its wiring's to provide.
- Declares erasure's own maintenance interface, which its wiring alone provides (internal module `maintenance`), and the one step a command under the maintenance key runs (internal module `step`).

## Not here
- What a subject's data is in each module and how it is erased: that module's eraser (`erasure-extensions`). The erasure journal: `erasure-journal` and its adapter.
- The store's maintenance key, control record and ledger: `store`, reached only through the maintenance interface, as its wiring (`account-erasure-store`) maps them.

## Offers
- Composition definition only, opt in: the full template composes it only where it is added.
- `erasureMaintenance`, on `.`: the maintenance interface, declared here for account-erasure alone to take (`takenBy`), provided by its wiring.

## Invariants
- It never depends on `store`. The wiring maps store's contracts and subject-records' phase onto the maintenance interface, each side's words its own.
- The check of `alone` catches provider processes of any version still attached after the operator's store cut-off. It does not prove that nobody else can touch the data.
  - `alone` holds at the moment asked: the store does not stop a later attach; the store cut-off does.
  - Every provider is counted: one that cannot run the store's commands on the data is refused at boot.

## Depends on
- `kernel`

## Vocabulary
- alone: no other process is attached to the store's data, as the store saw it when asked.
- accompanied {count}: other processes are attached; the count is the store's, for the operator to read.
- unchecked {reasons}: the store could not see every process that may be attached; the reasons are codes for the operator.
- not-in-maintenance: the maintenance key is not held.
- entered-not-shown-alone: `erasure-enter` set the key and was then not shown alone: the store answered `accompanied` or `unchecked`, or gave no answer (`unavailable`).
