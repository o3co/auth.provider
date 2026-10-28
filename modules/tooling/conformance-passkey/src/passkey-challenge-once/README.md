# passkey-challenge-once

Internal module of `conformance-passkey`: the fault scenes of a passkey challenge used once (`guarantee-5-h`).

## Responsibilities
- Checks, each scene after a control with no fault (a token issued for an assertion, and the assertion refused coming again), that over every use of one assertion, on every instance together, at most one token is issued, after:
  - its challenge's take losing its answer once, the resend taking the first answer, one issued (`Lr`); every answer lost, which answers unavailable, none issued (`Lx`);
  - a caught-up replica promoted (`F`); Redis killed at once and started again (`C`);
  - its instance killed after the take and before issuing, none issued, refused at another instance (`K`); one assertion sent to two instances at once, issued once when one take is let go after the other answered, and at most once when both are let go together (`H2`).

## Invariants
- A take's successes do not count a challenge's uses, so a challenge used once is told by: the tokens issued over its uses, counted from every instance's audit events (`token.issued`); every other use refused, recorded `challenge_invalid` (`passkey.login.refused`); and every use's take reaching the store, so the refusal was the store's.
- Each use comes within half the challenge's lifetime of its asking, so no use is refused for its challenge's age; a challenge never made is not the case, as the first use found it.

## Depends on
- `faults`; `conformance` (the fault scene's deployment, the relay's matches and the instance's audit trail)
