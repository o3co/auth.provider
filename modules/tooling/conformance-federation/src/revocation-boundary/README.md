# revocation-boundary

Internal module of `conformance-federation`: the fault scenes of a subject's revocation boundary refusing, from any instance, a federation grant established before it, and of the exception where grants keep on subject revocation (`guarantee-4-c`), the boundary written through the ledger's route.

## Responsibilities
- Reads, at another instance, a grant the user established before the boundary while the revocation's followers are held at their first write (session-lifecycle's, which federation-grants' follower runs after), so her grant's own follower has not ended it, and the revoking instance has written no grant.
- Asked for a token, the grant is judged by the boundary and written revoked by that read, `410` `grant_revoked`: the write at the reading instance tells it, the description (`backstop`) being the follower's and the sweep's too. Another subject's intent stands.
- Checks that, and that two instances revoking her at once create one boundary (counted by mark), both answering done, a third refusing the grant (`H2`).
- Checks the exception: where grants keep on subject revocation and the revocation keeps delegations, it writes her sessions' boundary alone, and the grant gives a token at another instance, before its followers run and after; a later revocation that ends delegations moves that boundary, and the grant is then refused as read, while a grant established after it answers (`H2`).
- After each refusal, a grant she establishes a second and more past the boundary's last write gives a token.

## Depends on
- `faults`; `conformance` (the relay's holds and matches)
