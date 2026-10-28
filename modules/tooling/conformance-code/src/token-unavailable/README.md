# token-unavailable

Internal module of `conformance-code`: the fault scenes of the token endpoint issuing no token for a code while a dependency its decision waits on cannot answer (`guarantee-3-b`).

## Responsibilities
- Checks, each scene after a control with no fault (a code used up by one write and a token issued for it), that the endpoint answers `503 temporarily_unavailable` with no token while:
  - the network is cut from the app to Redis, nothing reaching Redis (`Pu`), or from Redis to the app, Redis answering the read of the code's record the app never gets (`Pd`);
  - every connection is cut as it opens, nothing reaching Redis (`R`); Redis answers past the command timeout, the code's read answered only after the endpoint gave up (`L`); Redis sleeps, the endpoint answering before it wakes (`S`);
  - the primary holds its writes for a promotion, Redis running none of the redemption's calls until the endpoint gave up (`F`); the code's read is answered by one server and confirmed on another, the decision stopping before the use (`Fs`).
- Where the decision fails before the code's use (`Pu`, `Pd`, `R`, `L`, `S`, `F`, `Fs`), checks that no use of the code took effect.
- Checks that a decision made while Redis is killed at once and started again gives a token only where the code's use was kept by the server started again, and otherwise answers unavailable, saying which in its report (`C`).
- After each fault, the topology recovered, the endpoint gives a new code a token.

## Invariants
- One file of scenes per grant: a code's in `test/code.faults.case.ts`.
- The area lets requests go uncounted where the store fails (rate-limit's `fail-mode` open), so each scene reaches the redemption's own decision: the code's read, then its use.
- The scenes are this area's, not the OAuth area's: a code is issued only by the code flow, which this package composes over `conformance-oauth`'s parts.

## Depends on
- `faults` (the code flow, and the store's names for the code's read and use); `conformance` (the relay's faults and matches, the topology's promotion, sleep, crash and recovery)
