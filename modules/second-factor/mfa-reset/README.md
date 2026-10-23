# mfa-reset

## Responsibilities
- An operator's reset of a subject's second factors: ends the subject's sessions, removes every factor, releases the lockout, then ends the sessions again.
- A bridge to `mfa-flows`: it comes wherever `mfa-flows` is composed, so the one template can use the reset as it is.

## Not here
- Telling who asks for a reset, or whether they may (the embedder's). Removing factors (`mfa`). Moving the boundary (`subject-revocation`). The lockout's name and policy (`mfa-flows`, through its `flowParts`).

## Offers
- `mfaReset.run(subject, { requestedBy? })`, for an embedder that has verified who asks, answering how the run ended (`ResetOutcome`): `done` with `removed` (how many factors went) and their `kinds`, or `stopped` with `at` (`sessions`, `factors` or `lock`) where a step was unavailable, which running it again finishes; a failure not unavailable, at any step, is thrown.
  - A stopped run carries `removed` (`count`, `kinds`) where the factors' removal answered before it stopped: never at `factors`, always at `lock`, and at `sessions` only when the second boundary stopped it. Without it, whether the factors went is not known: a removal that failed after `mfa` removed the records (a witness that could not clear its mark) has taken them.
- Audit event (declared in `./audit-events`): `mfa.reset` once a run gets past its input, finished or not: `by` `operator`, `kinds` and `count` once the factors went, `sessions`, `sessionsAgain` once it ran, `complete`, and `requestedBy` when given.

## Invariants
- A subject that is not a non-empty string, or a requester that is not 1 to 256 well-formed characters, is refused with a RangeError before anything is done.
- Only the sessions boundary moves (`keepDelegations`); which delegated grants outlive it is for `federation-grants` to judge.
- Pending transactions are not touched: the boundary refuses them.
- A run that cannot move the first boundary, or whose revocation leaves a session open, stops there; a second revocation that leaves one open fails the run too.
- Otherwise a failed removal skips the release, and the second boundary moves whatever failed. The run answers `stopped` at the first failure's step, unless a failure at any step is not unavailable: that one is thrown.
- Under an enrollment witness, removing the factors (`mfa`'s `clear`) clears the witness's mark after them; a mark it cannot clear, or whose answer was lost, fails the run at `factors`, the subject left unable to log in, and the run must be made again.
- Only a reset clears that mark, and it may run only while the embedder keeps the subject isolated: no new login, session or enrollment, the running ones finished, and every earlier uncertain write to the witness settled.
- A finished run logs `mfa-flows.reset`, an unfinished one `mfa-flows.reset_incomplete` (`stoppedAt`: `sessions`, `factors` or `lock`; `error`: the error's type); the names stay `mfa-flows`' as operators know them.

## Depends on
- `kernel`, `audit`, `mfa` (composed with it), `mfa-managing` (`clear`), `rate-limit` (lockouts), `subject-revocation` (boundaries), `mfa-flows` (its lockout, through `flowParts`).
