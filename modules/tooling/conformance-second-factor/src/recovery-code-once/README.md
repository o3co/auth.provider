# recovery-code-once

Internal module of `conformance-second-factor`: the fault scenes of a recovery code used once (`guarantee-5-g`).

## Responsibilities
- Checks, each scene after a control with no fault (the code used up by one write that succeeds, and refused coming again with no such write), that a held login is let in once by a code and a later login is refused it after:
  - its use's answer lost once, the resend taking the first answer (`Lr`); every answer lost, which answers unavailable (`Lx`);
  - a caught-up replica promoted (`F`); Redis killed at once and started again (`C`);
  - its instance killed after the use and before answering, the same held login going on at another instance, which refuses the code and lets in a new one (`K`); one code used at two instances at once, taking effect once when one use is let go after the other answered, and letting in at most once when both are let go together (`H2`).

## Invariants
- A used code is refused `mfa_invalid` as a wrong one is; so a refusal as used is told by the instance's audit event (`mfa.verify.failure`, reason `replayed`, where a wrong code is `invalid`) and by no write of its use sent, and a race lost by the reason `raced`.

## Depends on
- `faults`; `conformance` (the fault scene's deployment, the relay's matches and the instance's audit trail)
