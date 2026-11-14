# verification

Internal module of `device-grant`: the interface the deployment's page calls, where a signed-in user looks up, approves or denies a code.

## Responsibilities
- Enters the session, counts the attempt, decides the code once, and records the decision to `audit`.

## Not here
- The route's declaration and its `csrf` policy (the package's). Issuing tokens (`grant`).

## Offers
- `verificationOver` (the build context) → `verificationWith` (`session`, `rate-limit`'s attempt limit, `audit`, `tokens`' admits, the store interfaces and the approvals, the runtime, the settings) → the route's handler and its answer to Unavailable, `503` `temporarily_unavailable`.


## Invariants
- An approval is put to `tokens`' issuance policies with its session once counted and found, before it is kept; a refusal is `access_denied`.
- Approve against deny is decided once by the device's record, a rewrite from `pending` that keeps no subject; a decision made first stands. An approval is kept apart (`approval-record`), holding the subject, the approval time, the session, its amr and its authentication time; whose approval is kept is the first created.
- An approval whose create could not be told is audited as `device.decision_outcome_unknown`, as a decision's write is. A device approved with no approval kept takes the next approver's, answered as a decision (200); after one is kept, `already_decided`.
- An approval for an erased subject is refused, `access_denied` with `subject_unknown`, audited as `device.approval_refused` naming no one (`outcome` `subject_unknown`, `withheld` `erased`); the device waits to its end.

## Depends on
- `session` (entry); `rate-limit` (attempts); `audit` (recording); `tokens` (admits); `token-endpoint` (OAuth error responses); `http` (the request and response, the source); `kernel` (the build context); the package's codes, record, `approval-record` and store interfaces
