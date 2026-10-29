# refresh-once

Internal module of `conformance-code`: the fault scenes of a refresh token rotated once (`guarantee-5-b`).

## Responsibilities
- Checks, each scene after a control with no fault (the token rotated by one write that succeeds, and refused coming again with no such write), that a refresh token is rotated once and refused as spent after:
  - its rotation's answer lost once, the resend taking the first answer and the token answered being the current one (`Lr`); every answer lost, which answers unavailable and gives no token (`Lx`);
  - a caught-up replica promoted, the rotation's token taken after (`F`); its session's entry, read after its family's record, confirmed on a server other than the one that answered it, which answers unavailable before the family rotates (`Fs`); Redis killed at once and started again, the rotation's token taken after (`C`);
  - its instance killed after the rotation and before answering, refused at another instance (`K`); one token sent to two instances at once, rotated once when one rotation is let go after the other answered and at most once when both are let go together, the loser a reuse that ends the family either way (`H2`).

## Depends on
- `faults`; `conformance` (the relay's matches)
