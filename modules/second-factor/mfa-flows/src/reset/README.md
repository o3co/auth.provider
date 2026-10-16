# reset

Internal module of `mfa-flows`: an operator's reset of a subject's second factors.

## Responsibilities
- Ends the subject's sessions, removes every factor and releases the lockout, then ends the sessions again.

## Not here
- Telling who asks for a reset, or whether they may (the embedder's). Removing factors (`mfa`). Moving the boundary (`subject-revocation`).

## Offers
- `resetOver` (`mfa`'s factor decisions, `subject-revocation`'s boundaries, `rate-limit`'s lockouts, `audit`) → the reset.

## Invariants
- A subject that is not a non-empty string, or a requester that is not 1 to 256 well-formed characters, is refused with a RangeError before anything is done.
- Only the sessions boundary moves (`keepDelegations`); which delegated grants outlive it is for `federation-grants` to judge.
- Pending transactions are not touched: the boundary refuses them.
- A run that cannot move the first boundary, or whose revocation leaves a session open, stops there; a second revocation that leaves one open fails the run too. Otherwise a failed removal skips the release, the second boundary moves whatever failed, and the first failure is the one answered.
- `mfa.reset` is recorded once a run gets past its input, finished or not: `by` `operator`, `kinds` and `count` once the factors went, `sessions`, `sessionsAgain` once it ran, `complete`, and `requestedBy` when given. A finished run logs `mfa-flows.reset`, an unfinished one `mfa-flows.reset_incomplete` (`stoppedAt`: `sessions`, `factors` or `lock`; `error`: the error's type).

## Depends on
- `audit`; `mfa` (factor decisions); `rate-limit` (lockouts); `subject-revocation` (boundaries); the package's section (the lockout's name)
