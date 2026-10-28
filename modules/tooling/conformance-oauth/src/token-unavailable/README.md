# token-unavailable

Internal module of `conformance-oauth`: the fault scenes of the token endpoint issuing no token for a JWT bearer assertion while the store cannot answer (`guarantee-3-d`).

## Responsibilities
- Checks, each scene after a control with no fault (the grant spends one assertion and gives a token), that the endpoint answers `503 temporarily_unavailable` with no token, the assertion's spend taking no effect, while:
  - the network is cut from the app to Redis, nothing reaching Redis (`Pu`), or from Redis to the app, Redis answering the subject's revocation boundary read the app never gets (`Pd`);
  - every connection is cut as it opens, nothing reaching Redis (`R`); Redis answers past the command timeout, the boundary read answered only after the endpoint gave up (`L`); Redis sleeps, the endpoint answering before it wakes (`S`);
  - the primary holds its writes for a promotion (`F`); the spend is answered by one server and confirmed on another (`Fs`).
- Checks that a decision made while Redis is killed at once and started again gives a token only where its spend was kept by the server started again, and otherwise answers unavailable, saying which in its report (`C`).
- After each fault, the endpoint gives a new assertion a token.

## Invariants
- The area lets requests by uncounted where the store fails (rate-limit's `fail-mode` open), so each scene reaches the grant's own decision: the boundary read, then the spend.

## Not here
- An issuer whose `jti` a ledger spends (`jti-ledger-http`): there the decision waits on that ledger over HTTP, outside Redis, and no scene here cuts it.

## Depends on
- `faults`; `conformance` (the relay's faults and matches, the topology's promotion, sleep and crash)
