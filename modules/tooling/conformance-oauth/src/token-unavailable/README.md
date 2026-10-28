# token-unavailable

Internal module of `conformance-oauth`: the fault scenes of the token endpoint issuing no token for a JWT bearer assertion while the store cannot answer (`guarantee-3-d`).

## Responsibilities
- Checks, each scene after a control with no fault (the grant spends one assertion and gives a token), that the endpoint answers `503 temporarily_unavailable` with no token while:
  - the network is cut from the app to Redis, nothing reaching Redis (`Pu`), or from Redis to the app, Redis answering the subject's revocation boundary read the app never gets (`Pd`);
  - every connection is cut as it opens, nothing reaching Redis (`R`); Redis answers past the command timeout, the boundary read answered only after the endpoint gave up (`L`); Redis sleeps, the endpoint answering before it wakes (`S`);
  - the primary holds its writes for a promotion (`F`); the spend is answered by one server and confirmed on another (`Fs`).
- Where the decision fails before the spend (`Pu`, `Pd`, `R`, `L`, `S`), checks that no spend of the assertion took effect.
- Under `Fs` the spend runs on the new primary and only its confirmation fails: no token is given, and the assertion stays spent, as nothing undoes a spend whose confirmation failed. A `503` is no token, not an assertion left unspent.
- Checks that a decision made while Redis is killed at once and started again gives a token only where its spend was kept by the server started again, and otherwise answers unavailable, saying which in its report (`C`).
- After each fault, the endpoint gives a new assertion a token.

## Invariants
- The area lets requests by uncounted where the store fails (rate-limit's `fail-mode` open), so each scene reaches the grant's own decision: the boundary read, then the spend.

## Not here
- An issuer whose `jti` a ledger spends (`jti-ledger-http`): there the decision waits on that ledger over HTTP, outside Redis, and no scene here cuts it.

## Depends on
- `faults`; `conformance` (the relay's faults and matches, the topology's promotion, sleep and crash)
