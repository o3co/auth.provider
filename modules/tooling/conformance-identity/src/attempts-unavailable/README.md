# attempts-unavailable

Internal module of `conformance-identity`: the fault scenes of password login's attempt limit letting no attempt by while the store cannot count (`guarantee-3-i`).

## Responsibilities
- Checks, each scene after a control with no fault (a login's attempt counted once, and a session opened), on a deployment whose request limits let requests by while the store fails (`rate-limit.fail-mode = open`), that a login is answered `503` `service_unavailable` with no session, nothing written to the identifier's lockout, while:
  - the network is cut from the app to Redis, nothing reaching Redis (`Pu`), or from Redis to the app, Redis counting an attempt the app never hears of (`Pd`);
  - every connection is cut as it opens, nothing reaching Redis (`R`); Redis answers past the command timeout, the count answered only after the login gave up (`L`); Redis sleeps, the login answering before it wakes (`S`);
  - the primary holds its writes for a promotion (`F`); the count is answered by one server and confirmed on another (`Fs`); Redis is killed at once under a held count and started again, the count never sent nor resent (`C`).
- After each fault, a login from a new source is counted and opens a session.

## Depends on
- `faults`; `conformance` (the relay's faults and matches, the topology's promotion, sleep and crash)
