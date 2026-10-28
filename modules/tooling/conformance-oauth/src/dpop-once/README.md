# dpop-once

Internal module of `conformance-oauth`: the fault scenes of a DPoP proof's `jti` spent once (`guarantee-5-e`).

## Responsibilities
- Checks, each scene after a control with no fault (the `jti` spent by one write that succeeds, and the proof refused, `invalid_dpop_proof`, coming again with no such write), that a token is issued once for a proof and the proof is refused coming again after:
  - its spend's answer lost once, the resend taking the first answer (`Lr`); every answer lost, which answers unavailable and gives no token (`Lx`);
  - a caught-up replica promoted (`F`); Redis killed at once and started again (`C`);
  - its instance killed after the spend and before answering, refused at another instance (`K`); one proof sent to two instances at once, spent once when one spend is let go after the other answered, and issuing at most once when both are let go together (`H2`).

## Invariants
- A proof out of its window is refused `invalid_dpop_proof` too, before its spend; so a replay's refusal is told by its description (`proof used before`) and by its spend, sent and finding the `jti` spent, and a scene that ran past the window does not pass on the proof's age.

## Depends on
- `faults`; `conformance` (the fault scene's deployment and the relay's matches)
