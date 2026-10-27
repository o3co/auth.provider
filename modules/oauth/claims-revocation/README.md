# claims-revocation

## Responsibilities
- Revokes, before a deployment goes back to a release before 0.19, every refresh family whose kept selection holds constraints, which such a release would refresh without them. Bridges `claims-selection` (the families listed) and `refresh` (their revocation).

## Not here
- Listing the families, and unlisting one whose selection ran out: `claims-selection`. Ending a family and the access tokens it issued: `refresh`. When to run, and what to wait for before and after: the operator, by the runbook's steps for going back.

## Offers
- Contract `constrainedFamilyRevocation`: `run()` → `not-draining` (with the mode) while `claims-selection` is not draining, revoking nothing; else `run`, with the families `revoked`, those `expired` (unlisted, not revoked), and what `failed`: parts of the list that could not be read (`shards`), selections that could not be read (`reads`), `revocations` and `removals`.

## Invariants
- It runs only while draining: outside it, a new constrained family may still start, so no run would be the last.
- A family is revoked as a session's close revokes it: its refresh tokens refused, and the access tokens it issued, refreshed or exchanged from it among them, revoked. A constrained access token with no family is not revoked; it runs out by itself.
- What fails stays listed, so a run again revokes it; revoking a family twice, or one that never started, is done.
- A run's `revoked` and nothing failed means only that every family listed when it ran was revoked: going back still waits for the longest access token lifetime after it.
- Comes once `claims-selection` and `refresh` are both composed, through `combinations` (`optIn`, joined); an app composed by hand composes it too to go back.

## Depends on
- `kernel`, `claims-selection`, `refresh`
