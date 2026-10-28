# authorize-unavailable

Internal module of `conformance-code`: the fault scenes of the authorization endpoint issuing no code while the store cannot answer (`guarantee-3-a`).

## Responsibilities
- Checks, each scene after a control with no fault (the endpoint keeps one new code and gives it), that the client is sent back `error=temporarily_unavailable` with no code, and no code kept, while:
  - the network is cut from the app to Redis, nothing reaching Redis (`Pu`), or from Redis to the app, Redis answering a read the app never gets (`Pd`);
  - every connection is cut as it opens, nothing reaching Redis (`R`); Redis answers past the command timeout, the read answered only after the endpoint gave up (`L`); Redis sleeps, the endpoint answering before it wakes (`S`);
  - the primary holds its writes for a promotion (`F`); a write is answered by one server and confirmed on another (`Fs`).
- Checks that a decision made while Redis is killed at once and started again gives a code only where its write was kept by the server started again, and otherwise answers unavailable, saying which in its report (`C`).
- After each fault, the endpoint gives a new request a code.

## Depends on
- `faults`; `conformance` (the relay's faults and matches, the topology's promotion, sleep and crash)
