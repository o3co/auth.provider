# erasure

Internal module of `passkeys`: erasing a subject's credentials and holder, fencing its registration challenges, and migrating their spaces, through the stores' ports.

## Responsibilities
- Is passkeys' eraser, `passkeys`, as its spaces' `erasedBy` names it, and states whether it can erase.

## Not here
- What a store's erasure removes or fences, and the tombstone (`subject-records`, behind the stores' ports). The ports' statement (`ports`). The record shapes and keys (`records`). When an eraser runs, and the run's report (`account-erasure`).

## Offers
- `passkeysEraser` (the passkey store, the registration challenge store where composed) → an `Eraser`: `online` erases the subject's credentials and holder and fences its registration challenges, a report for each space; `window` each subject in turn; `migrate` the credentials by `credentialSubjectOf`, then the holders by `holderSubjectOf`, then the registration challenges, a bounded space, which index none. `logoutGaps` is 0: it removes no session.
- `credentialSubjectOf`, and `holderSubjectOf` (the credentials, to read a holder's list) → a record's subject, as the migration reads it.

## Invariants
- A credential's subject is read from its value alone: a passkey, a pending one or a removal mark is its subject's, as passkeys writes all three. Its key is the hash of its id, which no field holds, so no key check guards it. Another shape is unreadable.
- A holder is its subject's where the subject it holds names its key (`s-` and the base64url SHA-256 of the subject); one whose subject names another key is unreadable.
- A holder holding no subject, as a node before 0.20 made it, is read by its credentials: one of them whose subject names its key gives it, a confirmed absent one passed over. Acceptance needs that key, so a wrong subject is a SHA-256 collision.
- A holder holding no subject none of whose credentials names its key reads as empty, and an empty holder is an orphan, removed: its key is a hash of a subject no field holds, so it holds no subject's data a reading can recover.
- A credential it lists that fails to read, or has another shape, makes the holder unreadable, never empty; so does a holder of another shape, read in `records`' shape.
- A registration challenge is never read: the migration answers a bounded space before any read, so a read asked of one is a defect, thrown.
- Where a subject's holder lists a 0.18 entry whose record is now another subject's, erasing that one makes it read absent; the holder's next emptying write answers `unsure`, which `passkey-witnessing` throws as inconsistent.
- `erasable` only where the passkey store offers `erase` and `migrate` in both spaces and a registration challenge store is composed offering both: without one, registration challenges, each holding its subject, stay in the challenge store, which cannot erase. Otherwise empty reports.

## Depends on
- `erasure-extensions` (the eraser and its readings); internal module `records` (`holderRead`, `keptOf`, `stored`, `subjectKey`, `credentialKey`); the package's store interface.
