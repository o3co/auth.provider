# rules

Internal module of `session`: the rules every implementation of `sessions` keeps alike, the stand-in too, offered as `sessionRules`.

## Responsibilities
- Holds entry at `credentials` to the floor where nothing judges it, and closes a subject's listed sessions in their one order.

## Not here
- When each is called, and what is logged of a failure (the implementation, or the stand-in).

## Offers
- `judgedShortOf`: the `entryJudge`'s answer (none contributed: admitted, nothing judged); then, at `credentials` where nothing judged it, a sign-in at a known time that the `recent` given holds recent, else `session` short with `step_up_required`. `credentialsSecondsDefault` (300), the stand-in's window.
- `closeListed`: closes each listed session of a subject through the close given, one at a time in the listing's order, past one that fails or is left pending, and then fails.

## Depends on
- `kernel` (Unavailable); `session`'s contract.
