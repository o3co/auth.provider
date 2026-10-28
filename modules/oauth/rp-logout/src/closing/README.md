# closing

Internal module of `rp-logout`: the close a logout asks, the same whichever route asked it.

## Responsibilities
- Reads what the close forgets (the session's clients, the upstream's end of session), closes the session, and records the outcome.
- Holds the one handling of a close that the hinted logout and a confirmed logout share, so both end a session alike.

## Not here
- Which session to close, and whether the request may close it (`ending`, `confirm`). The answer to the browser (the route's). Building the page (`page`).

## Offers
- `closingOver` → (request, the sid, the subject the request named if any, the return) → unavailable, pending, no logout of its own (a session closed before, or gone), or logged out with the upstream's end of session and the frames of its clients.

## Invariants
- The session's clients and the upstream's end of session are read before the close, which forgets the upstream tokens.
- Nothing reads the session itself before its close: a read can end one past its lifetime without its participants. Whether it is the logout comes from what the close found; a session past its lifetime whose record the close found is logged out, its participants called.
- `logout.success` for a logout, with the subject and `sid`, and `source` and `userAgent` when known; `logout.close_pending` for a pending close; `logout.cascade_failed` (with `store` `session`) for a close that is unavailable. A session closed before, or gone, records nothing.
- A client record that cannot be read leaves out its frame, logged as `rp-logout.client_unavailable`.

## Depends on
- `audit`, `clients`, `kernel`, `request-source` (the source), `session` (close); the package's contract, store interfaces, `page` (the frame's form) and `registration`
