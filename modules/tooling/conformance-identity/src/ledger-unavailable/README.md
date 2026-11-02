# ledger-unavailable

Internal module of `conformance-identity`: the fault scenes of the ledger's subject revocation route answering done only once every step's dependency answered (`guarantee-3-l`).

## Responsibilities
- Holds each answer to what the store took meanwhile: done only where the subject's boundary, a follower's first write (session-lifecycle adding the subject's sessions to its closings) and its work (a session's record closed) all succeeded; `incomplete` only where the boundary did; `unknown` only where no follower's write did.
- Checks, each scene after a control with no fault (the boundary written, a follower run, done answered), with the subject holding a session so its followers have work, that:
  - with the network cut from the app to Redis, the route answers with no `state` before its window counts, `unknown` at the boundary's write, and `incomplete` at a follower's first write (`Pu`);
  - held at the boundary's write, it answers `unknown` while Redis's answers are cut (`Pd`), Redis answers past the command timeout (`L`), Redis sleeps past the route's patience (`S`), the primary holds writes for a promotion (`F`), or the write is confirmed on another server (`Fs`);
  - every connection cut as it opens, and Redis killed at once and started again, it answers done only where every step was answered, saying which way it went (`R`, `C`; under `C`, by the server started again).
- After each fault, the revocation sent again is done.

## Depends on
- `faults`; `conformance` (the relay's faults and matches, the topology's promotion, sleep and crash)
