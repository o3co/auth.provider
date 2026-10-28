# id-token-once

Internal module of `conformance-exchange`: the fault scenes of an Apple id_token taken once, whether by the token exchange or as a JWT bearer assertion, in exchange-id-tokens' one record (`guarantee-5-j`).

## Responsibilities
- Checks, each scene after a control with no fault (an id_token taken by one write that succeeds, by either grant, then refused by both with no such write), that an id_token is taken once and refused by both grants after:
  - the exchange's take losing its answer once, the resend taking the first answer (`Lr`); every answer lost, which answers unavailable and gives no token (`Lx`);
  - a caught-up replica promoted (`F`); Redis killed at once and started again (`C`);
  - its instance killed after the exchange took it and before answering, refused at another instance (`K`);
  - one id_token exchanged at one instance and asserted at another at once (`H2`): taken once when the assertion's take is let go first, the exchange then giving back what it issued; at most once issued when both are let go together, the other refused by its own grant.
- After each fault, a new id_token is exchanged.

## Invariants
- Apple's issuer and key set stay as exchange-id-tokens fixes them: the scenes reach Apple's own host (`faults`).
- Each grant's refusal of an id_token taken is told by its description (`subject_token has been used`, `assertion replayed`) and by its take, sent and finding it taken.
- The faults are on the token exchange's take. The JWT bearer grant's take is the same take on the same record, and is faulted only where `H2` crosses the two grants.
- After a promotion or a crash, a scene waits for the topology to recover, every replica online and as many good as a write asks, before the writes that follow.

## Depends on
- `faults`; `conformance` (the fault scene's deployment and the relay's matches)
