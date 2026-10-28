# revocation-boundary

Internal module of `conformance-device`: the fault scenes of a subject's revocation boundary refusing, from any instance, a device code approved before it (`guarantee-4-b`), the boundary written through the ledger's route.

## Responsibilities
- Reads, at another instance, a device the user approved before the boundary while the revocation's followers are held at their first write (session-lifecycle, the only follower composed), so the approving session is not closed: the poll is `invalid_grant`, refused before it takes the approval, which is never written.
- Checks, each scene after a control with no fault (a device approved at one instance is polled for a token at another), that the device gives no token at another instance while the followers are still to run, and that two instances revoking the user at once create one boundary (counted by mark), both answering done, a third refusing the device (`H2`).
- After each fault, a device the user approves from a login after the boundary (past its second, as boundaries are compared in seconds) gives a token.

## Depends on
- `faults`; `conformance` (the relay's holds and matches)
