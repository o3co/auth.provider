# mfa-revocation

## Responsibilities
- Moves a revoked subject's fence in `mfa`, so that no second-factor binding begun before a revocation binds once the revocation is complete. Bridges `mfa` and `subject-revocation`.

## Not here
- The fence, and what a binding does on finding it moved: `mfa`.
- Recording a revocation and calling its followers: `subject-revocation`.

## Offers
- Contribution to `subject-revocation`'s followers, under `mfa`'s `fenceFollower`: asks `mfa`'s `fence` for the subject revoked.

## Invariants
- A revocation is complete only once the fence moved; while `mfa` cannot move it, the revocation answers incomplete.
- Safe to call again and from several hosts at once: the fence only moves further, stopping at most a binding more.
- Comes once `mfa` and `subject-revocation` are both composed, through `combinations`; `mfa-flows` refuses boot without it.

## Data
- None.

## Depends on
- `kernel`, `mfa` (composed with it, and its `fenceFollower`), `mfa-managing` (`fence`), `subject-revocation`
