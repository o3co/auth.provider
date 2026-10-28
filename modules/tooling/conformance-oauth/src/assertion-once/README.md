# assertion-once

Internal module of `conformance-oauth`: the fault scenes of a JWT bearer assertion's `jti` spent once (`guarantee-5-c`).

## Responsibilities
- Checks, each scene after a control with no fault (the `jti` spent by one write that succeeds, and the assertion refused coming again with no such write), that an assertion is taken once and refused as spent after:
  - its spend's answer lost once, the resend taking the first answer (`Lr`); every answer lost, which answers unavailable and gives no token (`Lx`);
  - a caught-up replica promoted (`F`); Redis killed at once and started again (`C`);
  - its instance killed after the spend and before answering, refused at another instance (`K`); one assertion sent to two instances at once, spent once when one spend is let go after the other answered, and at most once taken when both are let go together, the other refused as a replay (`H2`).

## Not here
- An issuer whose `jti` a ledger spends (`jti-ledger-http`): there the assertion is taken once by that ledger, outside Redis, and no scene here checks it.

## Depends on
- `faults`; `conformance` (the fault scene's deployment and the relay's matches)
