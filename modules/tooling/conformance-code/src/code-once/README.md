# code-once

Internal module of `conformance-code`: the fault scenes of an authorization code redeemed once (`guarantee-5-a`).

## Responsibilities
- Checks, each scene after a control with no fault (the code used up by one write that succeeds, and refused coming again with no such write), that a code is redeemed once and refused as used after:
  - its use's answer lost once, the resend taking the first answer (`Lr`); every answer lost, which answers unavailable and issues nothing (`Lx`);
  - a caught-up replica promoted (`F`); its record confirmed on a server other than the one that answered it, which answers unavailable before the code is used (`Fs`); Redis killed at once and started again (`C`);
  - its instance killed after the use and before answering, refused at another instance (`K`); one code sent to two instances at once, issued once (`H2`);
  - an instance's clock moved forward and back, its lifetime on Redis's clock (`Ta`, on glibc Linux, never skipped in a fault run).

## Depends on
- `faults`; `conformance` (the relay's matches and the fault run)
