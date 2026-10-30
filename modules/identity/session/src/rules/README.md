# rules

Internal module of `session`: the rules every implementation of `sessions` keeps alike, the stand-in too, offered as `sessionRules`.

## Responsibilities
- Holds entry at `credentials` to the floor where nothing judges it, closes a subject's listed sessions in their one order, and reads a login's authentication time.

## Not here
- When each is called, and what is logged of a failure (the implementation, or the stand-in).

## Offers
- `judgedShortOf`: the `entryJudge`'s answer (none contributed: admitted, nothing judged); then, at `credentials` where nothing judged it, a sign-in at a known time that the `recent` given holds recent, else `session` short with `step_up_required`. `credentialsSecondsDefault` (300), the stand-in's window.
- `closeListed`: closes each listed session of a subject through the close given, one at a time in the listing's order, past one that fails or is left pending, and then fails.
- `checkAuthenticatedAt`: a `TypeError`, naming no value, for a login's authentication time neither epoch milliseconds (0 to 8.64e15), `opening` nor `unknown`. `authenticatedAtOf` (the login's facts, the opening, what to do where it caps a later time) → the time the session keeps; the stand-in reads a login by them.

## Invariants
- A login's authentication time is kept (a raise included): the opening for a login the provider authenticates itself (`opening`), so a gate's wait never ages it; an upstream's login keeps the time the upstream reports (as `federation` places it), the opening time when it gives a later one; one it reports unknown is answered as `authenticatedAtUnknown` and never counts as fresh. The lifetime, the cookie and the subject's revocation boundary count from the opening instead.

## Depends on
- `kernel` (Unavailable); `session`'s contract.
