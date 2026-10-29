# revocation-boundary

Internal module of `conformance-exchange`: the fault scenes of a subject's revocation boundary refusing, from any instance, the exchange of a token given before it (`guarantee-4-e`), the boundary written through the ledger's route.

## Responsibilities
- Exchanges, at another instance, an access token the user was given before the boundary while the revocation's followers are held at their first write (session-lifecycle, the only follower composed), so her session is not closed: the exchange is `invalid_request` with the subject token's own check failed, which a closed session or an ended family would be described apart from; another user's token is exchanged.
- Checks, each scene after a control with no fault (a token given at one instance is exchanged at another), that no token is exchanged at another instance while the followers are still to run, and that two instances revoking the user at once create one boundary (counted by mark), both answering done, a third refusing the exchange (`H2`).
- After each fault, a token the user is given from a login a second and more past the boundary's last write is exchanged.

## Depends on
- `faults`; `conformance` (the relay's holds and matches)
