# sweep

Internal module of `federation-grants`: erasing the credentials of grants no request reads.

## Responsibilities
- On each host, every `sweep-interval`, walks every grant kept and erases the credentials of one past its end, or ended by its subject's revocation.

## Not here
- Answering a grant's state (the routes, which judge it on each read). Ending a grant's intent (judged when the intent is used). The listing a revocation's follower walks (`api`).

## Offers
- `sweepWith` (the grants, records, judge, audit, clock, randomness, log) → one pass, stopping at the stop signal; `sweepIn` (the build context, the shared parts, audit) starts it every `sweep-interval`.

## Invariants
- Only a grant holding credentials is judged; one already lapsed, revoked or still pending is passed over.
- A grant past its end, judged again on the record as written, loses its credentials under a new version, its status kept to be answered; a refresh that read it before writes nothing back.
- A grant its subject's revocation ends is written revoked (`backstop`), without credentials, and recorded as `federation.grant.revoked`: also one the subject's listing missed, which the follower never reaches.
- The revocation is judged outside the write and bound to the subject and the authorization it was judged on; a grant authorized again since is read and judged once more, and else left to the next pass.
- A pass that cannot read a page stops (`federation-grants.sweep_incomplete`); the next starts again from the first. A grant it cannot sweep is counted (`federation-grants.sweep_failed`) and passed.
- Every write is a change over the record as it is, so two hosts sweeping one grant write it once.
- A pass reads every record kept (a grant lives its lifetime and 30 days more, to answer its state), and the boundary once or twice for each grant holding credentials, on every host: its cost grows with the grants kept and the hosts.
- A host whose clock runs ahead may lapse a grant early; another host then answers it as needing reauthorization, not as expired.
- A correct reauthorization after a lapse may bring new credentials; the sweep leaves a grant not ended alone.
- How soon credentials go is not bounded: while passes keep running, those of an ended grant go; with the store answering and a pass done within `sweep-interval`, about that long after the end.

## Depends on
- `kernel` (the build context, the clock, randomness, every), `audit`; the package's grant records, judge, store interfaces and audit events.
