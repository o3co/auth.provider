# revocation-boundary

Internal module of `conformance-code`: the fault scenes of a subject's revocation boundary refusing, from any instance, the session and tokens made before it (`guarantee-4-a`), the boundary written through the ledger's route.

## Responsibilities
- Reads, at another instance, what a user's login made before the boundary while the revocation's followers are held at their first write, so nothing the followers clean up refuses: the session lets no one in, a code not yet redeemed gives nothing (used up before it is checked, it has no token noted on it), a refresh token is not rotated, both access tokens (the code's and a session grant's) are inactive, and no session grant is given; another user's login is untouched.
- Checks, each scene after a control with no fault (the boundary written, its followers run, done answered, and what was made refused), that:
  - a boundary whose write's answer is lost once is resent under its mark and refuses, the revocation done once its followers run (`Lr`); one whose every answer is lost is never answered done and still refuses, no follower called (`Lx`);
  - a boundary confirmed before a caught-up replica is promoted refuses after it, the revocation answered incomplete as its followers could not finish (`F`); one confirmed before Redis is killed at once and started again refuses after it, read before the followers could run again, the revocation answered done only where they then finished (`C`);
  - a boundary whose instance was killed after writing it and before answering refuses at another (`K`); a boundary refuses at another instance while its followers are still to run, and two instances revoking a subject at once create one boundary, both answering done (`H2`).
- After each fault, the revocation sent again finishes, and another user's new login passes.
- Keeps `tokens.subject-check` at its default; its exception is not checked here.

## Depends on
- `faults`; `conformance` (the relay's faults and matches, the topology's promotion and crash, an instance's kill); `conformance-oauth` (clients)
