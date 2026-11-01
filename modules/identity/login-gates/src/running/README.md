# running

Internal module of `login-gates`: a login through the gates, and a held one resumed.

## Responsibilities
- Asks the gates in their order, and has `session` open the login once every gate passes it.
- Resumes a held login after the gate that held it, telling the caller once it opens.

## Offers
- `runningWith` (the gates in order, the callers told after a hold by name, `session`'s opening, the clock, the log) → `login` and `resume`, as `logins` offers them.

## Invariants
- The first gate that refuses or holds ends the run; a held login answers the gate's answer and cookies.
- On resume, the gates before the one that held it marked `rechecked` are asked again and may only pass or refuse; one holding there is the gate's error.
- A resume past its deadline is `expired`, before any gate is asked; one naming no gate is a TypeError.
- A caller named that contributed nothing is a TypeError, at login and at resume alike; what a caller does with the news never closes the login, and a throw is logged `login-gates.opened_failed` by kind.

## Depends on
- `session` (the opening), `kernel` (the clock and the log).
