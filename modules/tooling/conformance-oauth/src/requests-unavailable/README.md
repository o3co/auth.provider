# requests-unavailable

Internal module of `conformance-oauth`: the fault scenes of the token endpoint's request limit letting no request by while the store cannot count, its fail mode closed (`guarantee-3-h`).

## Responsibilities
- Checks, each scene after a control with no fault (a request counted once and given a token), that the endpoint answers `503 service_unavailable`, the limit's own answer and not the grant's `temporarily_unavailable`, with no token while:
  - the network is cut from the app to Redis, nothing reaching Redis (`Pu`), or from Redis to the app, Redis counting the request the app never hears of (`Pd`);
  - every connection is cut as it opens (`R`); Redis answers past the command timeout, the count answered only after the endpoint gave up (`L`); Redis sleeps, the endpoint answering before it wakes (`S`);
  - the primary holds its writes for a promotion (`F`); Redis is killed under the count and started again, the count, which carries no mark to resend under, sent no more (`C`).
- Checks that none of the grant's calls (the subject's revocation boundary read, the assertion's spend) was sent from the fault on: the request was refused at its count.
- After each fault, a new request is counted and given a token.

## Invariants
- The scenes set `rate-limit.fail-mode` to `closed`, the deployment's default; the area's other fault scenes set `open`, to reach the grant.
- No `Fs` scene: the request windows ask no replication, so no confirmation round can split.

## Depends on
- `faults`; `conformance` (the relay's faults and matches, the topology's promotion, sleep and crash)
