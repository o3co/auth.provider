# fence

Internal module of `conformance-second-factor`: the fault scenes of a subject's fence refusing, from another instance, a change to her second factors that her revocation overtook (`guarantee-4-d`), the revocation sent through the ledger's route.

## Responsibilities
- Races each change with the revocation: at one instance, a session opened before it asks the change, which passes the session's checks (each reads her boundary, as the scene checks) and has its one write to her factor list held; at another, the revocation is answered complete, its follower mfa-revocation having moved her fence in that list; let go, the change finds the list changed, decides again on the fence moved, and is refused, no write of its succeeding.
- Checks that the race removes no factor (her factor still listed at a new login), reissues no recovery codes (a code from before still lets her in), and binds no factor whose enrollment was begun before (her TOTP the one she had) (`H2`).
- Each after a control with no fault (the session reissues her recovery codes), and each new login a second and more past the boundary, as boundaries are compared in seconds.

## Not here
- A change asked after the revocation: refused before, as her sessions are closed, which proves nothing of the fence.

## Depends on
- `faults`; `conformance` (the relay's holds and matches)
