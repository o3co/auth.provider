# raise

Internal module of `session-lifecycle`: raising a session's authentication (step-up).

## Responsibilities
- Adds to the request's live session the amr a further authentication proved, under a new cookie.

## Not here
- Whether a session is live (`lifecycle`).
- Minting and retiring cookie secrets, and the record codec (`lifecycle`).
- What proves the further authentication (its caller).

## Offers
- `raiseOver`: the lifecycle, the session store, the clock and the lifetime → `session`'s raise, as `session-lifecycle` provides it.
- A raise answers the raised session and a new cookie.
- When the record cannot be written, a raise answers the session not raised and the new cookie.
- Without a live session, a raise answers nothing.
- `raisedBy`: a session's amr after a raise, and what the raise added, each value once.

## Invariants
- A raise keeps the handle and the authentication time.
- It writes the new secret's index, confirms the removal of the old one, then raises the record.
- When the removal cannot be confirmed, the raise is unavailable (it becomes a logout).
- The new cookie lives for what is left of the session, counted from its opening.

## Depends on
- `kernel` (the clock); `lifecycle`; `session`'s contract; `session-lifecycle`'s session store.
