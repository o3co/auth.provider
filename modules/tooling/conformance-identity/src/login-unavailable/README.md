# login-unavailable

Internal module of `conformance-identity`: the fault scenes of password login opening no session while the store cannot answer (`guarantee-3-f`).

## Responsibilities
- Checks, each scene after a control with no fault (a login writes its session's record and its cookie's index, and opens it), a login whose attempt is counted and whose first session write is held when the fault comes, so the attempt limit is past and the session is what the store cannot keep.
- Checks that the login is answered `503` `temporarily_unavailable` with no session, and that no session is indexed under a cookie from the fault on, while:
  - the network is cut from the app to Redis, nothing reaching Redis (`Pu`), or from Redis to the app, Redis writing a record the app never hears of (`Pd`);
  - every connection is cut as it opens, no store operation reaching Redis (`R`); Redis answers past the command timeout, the record reaching it only past that (`L`); Redis sleeps past the record's patience, the login answering before it wakes (`S`);
  - the primary holds its writes for a promotion (`F`); the record is written on one server and confirmed on another (`Fs`).
- Checks that a login made while Redis is killed at once and started again opens a session only where its record and index were kept by the server started again, and otherwise answers unavailable with none, saying which in its report (`C`).
- After each fault, a new login opens a session.

## Depends on
- `faults`; `conformance` (the relay's faults and matches, the topology's promotion, sleep and crash)
