# mfa-reset

## Responsibilities
- An operator's reset of a subject's second factors: ends the subject's sessions, removes every factor, releases the lockout, then ends the sessions again.
- A bridge to `mfa-flows`: it comes wherever `mfa-flows` is composed, so the one template can use the reset as it is.

## Not here
- Telling who asks for a reset, or whether they may (the embedder's). Removing factors (`mfa`). Moving the boundary (`subject-revocation`). The lockout's name and policy (`mfa-flows`, through its `flowParts`).

## Offers
- `mfaReset.reset(subject, { requestedBy? })`, for an embedder that has verified who asks: answers how many factors went.
- A reset that cannot do a step rejects as unavailable; running it again finishes it.
- Audit event (declared in `./audit-events`): `mfa.reset` once a run gets past its input, finished or not: `by` `operator`, `kinds` and `count` once the factors went, `sessions`, `sessionsAgain` once it ran, `complete`, and `requestedBy` when given.

## Invariants
- A subject that is not a non-empty string, or a requester that is not 1 to 256 well-formed characters, is refused with a RangeError before anything is done.
- Only the sessions boundary moves (`keepDelegations`); which delegated grants outlive it is for `federation-grants` to judge.
- Pending transactions are not touched: the boundary refuses them.
- A run that cannot move the first boundary, or whose revocation leaves a session open, stops there; a second revocation that leaves one open fails the run too.
- Otherwise a failed removal skips the release, the second boundary moves whatever failed, and the first failure is the one answered.
- Under an enrollment witness, removing the factors (`mfa`'s `clear`) clears the witness's mark after them; a mark it cannot clear, or whose answer was lost, fails the run at `factors`, the subject left unable to log in, and the run must be made again.
- Only a reset clears that mark, and it may run only while the embedder keeps the subject isolated: no new login, session or enrollment, the running ones finished, and every earlier uncertain write to the witness settled.
- A finished run logs `mfa-flows.reset`, an unfinished one `mfa-flows.reset_incomplete` (`stoppedAt`: `sessions`, `factors` or `lock`; `error`: the error's type); the names stay `mfa-flows`' as operators know them.

## Depends on
- `kernel`, `audit`, `mfa` (composed with it), `mfa-managing` (`clear`), `rate-limit` (lockouts), `subject-revocation` (boundaries), `mfa-flows` (its lockout, through `flowParts`).
