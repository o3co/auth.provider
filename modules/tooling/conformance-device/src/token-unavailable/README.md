# token-unavailable

Internal module of `conformance-device`: the fault scenes of the token endpoint issuing no token for a device code while the store cannot answer (`guarantee-3-e`).

## Responsibilities
- Checks, each scene after a control with no fault (an approved device's poll takes its approval once and gives a token), that a poll is answered `503 temporarily_unavailable` with no token while:
  - the network is cut from the app to Redis, nothing reaching Redis (`Pu`), or from Redis to the app, Redis answering a call the app never gets (`Pd`);
  - every connection is cut as it opens, the take not succeeding (`R`); Redis answers past the command timeout, a call answered only after the endpoint gave up (`L`); Redis sleeps, the endpoint answering before it wakes (`S`);
  - the primary holds its writes for a promotion (`F`); a call runs on one server and is confirmed on another, the new primary first taking writes, and no take is written (`Fs`).
- Where the decision fails before the take (`Pu`, `Pd`, `R`, `L`, `S`, `F`), checks that no take of the approval succeeded and that, once healed, the same device gives a token.
- Checks that a poll made while Redis is killed at once and started again gives a token only where its take was kept by the server started again, and otherwise answers unavailable, saying which in its report (`C`).
- After each fault, a newly approved device gives a token.

## Invariants
- The area lets requests by uncounted where the store fails (rate-limit's `fail-mode` open, as the OAuth part sets it), so each scene reaches the device grant's own decision.

## Depends on
- `faults`; `conformance` (the relay's faults and matches, the topology's promotion, sleep and crash)
