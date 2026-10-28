# client-assertion-once

Internal module of `conformance-oauth`: the fault scenes of a client assertion's `jti` spent once (`guarantee-5-d`).

## Responsibilities
- Checks, each scene after a control with no fault (the `jti` spent by one write that succeeds, and the client refused, `invalid_client`, sending it again with no such write), that a client authenticates once by an assertion and is refused sending it again after:
  - its spend's answer lost once, the resend taking the first answer (`Lr`); every answer lost, which answers unavailable and gives no token (`Lx`);
  - a caught-up replica promoted (`F`); Redis killed at once and started again (`C`);
  - its instance killed after the spend and before answering, refused at another instance (`K`); one assertion sent to two instances at once, spent once when one spend is let go after the other answered, and authenticating at most once when both are let go together (`H2`).

## Invariants
- An expired assertion is refused `invalid_client` too, naming no reason, before its spend; so a refusal after a fault is told by its spend, sent and finding the `jti` spent, and a scene that ran past the assertion's life does not pass on its age.

## Depends on
- `faults`; `conformance` (the fault scene's deployment and the relay's matches)
