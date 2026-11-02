# revocation-unavailable

Internal module of `conformance-oauth`: the fault scenes of the revocation endpoint answering done only once a token's revocation is kept (`guarantee-3-g`).

## Responsibilities
- Checks, each scene after a control with no fault (an active token's revocation written once and answered done, the token then inactive), that the endpoint answers `503 temporarily_unavailable`, never done, while:
  - the network is cut from the app to Redis, nothing reaching Redis (`Pu`), or from Redis to the app, Redis answering the store's clock read the app never gets (`Pd`);
  - every connection is cut as it opens, nothing reaching Redis (`R`); Redis answers past the command timeout, the clock read answered only after the endpoint gave up (`L`); Redis sleeps past the write's patience, the endpoint answering before it wakes (`S`);
  - the primary holds its writes for a promotion, Redis running none of the route's calls until the endpoint gave up (`F`); the revocation is written on one server and confirmed on another (`Fs`).
- Where the route gives up before the revocation (`Pd`, `L`, `F`), checks that no revocation was written; under `Pd` and `L` the token is still active, so nothing was revoked that the answer did not say.
- Under `Fs` the revocation is written on the new primary and only its confirmation fails: the endpoint answers unavailable though the token may stay revoked. A `503` is no promise that nothing was revoked.
- Checks that a revocation made while Redis is killed at once and started again is answered done only where the server started again kept it, and otherwise unavailable, saying which in its report (`C`).
- After each fault, the token revoked again is answered done and inactive, as is a new, active token.

## Invariants
- The area lets requests by uncounted where the store fails (rate-limit's `fail-mode` open), so each scene reaches the route's own calls: the store's clock, read for the write's deadline, then the revocation.
- `S` sleeps longer than the write's patience (10 s): a shorter sleep lets a resend after Redis wakes be confirmed, and the route rightly answers done.

## Not here
- The refresh token and other kinds a module contributes to the revocation endpoint; the access token alone is revoked here.

## Depends on
- `faults`; `conformance` (the relay's faults and matches, the topology's promotion, sleep and crash)
