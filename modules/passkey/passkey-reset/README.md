# passkey-reset

## Responsibilities
- An operator's reset of a subject's passkeys: ends the subject's sessions, empties its passkey list, then ends the sessions again.
- The passkeys' step alone, for `mfa-reset`'s parts, which move the boundaries themselves.

## Not here
- Telling who asks for a reset, or whether they may (the embedder's). Emptying the list and withdrawing the witness's mark (`passkeys`, through `passkeyHolders.cleared`). Moving the boundary (`subject-revocation`). Contributing the step to `mfa-reset` (the bridge `mfa-reset-passkeys`).

## Offers
- `passkeyReset.reset(subject, { requestedBy? })`, for an embedder that has verified who asks, answering how the run ended (`PasskeyResetOutcome`): `done` with `removed`, or `stopped` with `at` (`sessions` or `passkeys`) at the first step that was unavailable, which running it again finishes; a failure not unavailable, at any step, is thrown.
  - A stopped run carries `removed` only where the second boundary stopped it, the removal having answered. Without it, whether the list went is not known.
  - `removed` counts the list entries the run took off, pending ones and old entries 0.18 left among them: not the passkeys that could log in.
- `passkeyResetPart.passkeys(subject)`, taken by `mfa-reset-passkeys` alone: empties the list without moving a boundary, answering `done` with `removed`, or `stopped` where the removal was unavailable; any other failure is thrown. It records nothing: `mfa.reset` does.
- Audit event (declared in `./audit-events`): `passkey.reset` once a run gets past its input, finished or not: `by` `operator`, `count` once the removal answered, `sessions`, `sessionsAgain` once it was tried, `complete`, and `requestedBy` when given.

## Invariants
- A subject that is not a non-empty well-formed string, or a requester that is not 1 to 256 well-formed characters, is refused with a RangeError before anything is done.
- Only the sessions boundary moves (`keepDelegations`). A run that cannot move the first boundary, or whose revocation leaves a session open, stops there; once it moved, the second boundary is tried whatever the removal did.
- The run answers the first step that failed, unless a failure at any step is not unavailable: that one is thrown, once the run is recorded.
- `takenBy` binds modules, not who composes them: the embedder's own code can take `passkeyResetPart`, and is trusted to run it only under `mfa-reset`'s boundaries.
- `done` is every step run, not no passkey left. Boundaries compare in whole seconds: a registration challenged after the first boundary's second and before the second boundary, written after the removal and admitted before the second boundary, stays usable; so does one challenged after the second boundary's second. Recovering from a leaked passkey needs the subject held first: no new login, session or registration, the running ones finished.
- The removal's limits are `passkeys`': a store gone back to a copy taken after the removal's write can let a registration made meanwhile lose its mark; a mark withdrawn whose answer was lost, or a read after it that stopped, may leave no mark, the run stopped.
- Records 0.18 left on no list stay in the store and log no one in. While a 0.18 instance runs, which writes the list and records apart, these guarantees hold only once it and its requests are gone.
- A finished run logs `passkey-reset.reset`, an unfinished one `passkey-reset.reset_incomplete` (`stoppedAt`: `sessions` or `passkeys`; `error`: the error's type).

## Depends on
- `kernel`, `audit`, `passkeys` (`passkeyHolders`), `subject-revocation` (boundaries).
