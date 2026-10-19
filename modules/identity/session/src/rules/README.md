# rules

Internal module of `session`: the rules every implementation of `sessions` keeps alike, the stand-in too, offered as `sessionRules`.

## Responsibilities
- Calls a closing session's participants, asks the entry requirements, and closes a subject's listed sessions, each in its one order.

## Not here
- When each is called, and what is logged of a failure (the implementation, or the stand-in).

## Offers
- `failedParticipants`: calls the participants one at a time in collect order, past a failing one, and answers each that failed by name and the error's kind; none when all finished.
- `firstShortOf`: asks the requirements in name order and answers the first that falls short, by its name and answer.
- `entryShortOf`: the same, then, at `credentials` where no requirement judges it, a sign-in at a known time within the milliseconds given (300 s by default), else `session` short with `step_up_required`; `credentialsSecondsDefault` (300).
- `judgedShortOf`: the `entryJudge`'s answer (none contributed: admitted, nothing judged), then the same `credentials` floor, by the `recent` given.
- `closeListed`: closes each listed session of a subject through the close given, one at a time in the listing's order, past one that fails or is left pending, and then fails.

## Depends on
- `kernel` (Unavailable); `session`'s contract.
