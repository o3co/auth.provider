# handoff

Internal module of `federation`: handing the upstream tokens of a login to the receivers.

## Responsibilities
- Tells every receiver the upstream tokens of a login once its session opens: at once, or, when a gate held the login, when `login-gates` says it opened. A link's tokens go at once to the open session it joined.
- Keeps the tokens of a held login sealed until then.

## Not here
- The login, its transaction and the local user (`round-trip`). What a receiver keeps (the receiver). How sealing works (`seal`).

## Offers
- `handoffIn` and `openedIn`: from the build context, the handoff over the receivers in name order (`noHandoff` where there are none), and `login-gates`' news that a held login opened.
- `handoffWith` (receivers, `seal`, transaction store, `kernel`'s runtime, lifetime):
  - for one login: the `from` that `login-gates` carries and what follows the login's outcome
  - `opened` (session, carry), for `login-gates`
  - `joined` (session, IdP, tokens), for a link, handed at once: a receiver failing undoes those given (`withdrawn`) and is unavailable, logged as `federation.link_join_failed`
  - `withdrawn` (session, IdP) takes a link's tokens back from every receiver; an undo that fails is logged as `federation.link_join_undo_failed`, and the rest still go
- `noHandoff`, where no module receives upstream tokens

## Invariants
- Only a login whose upstream gave tokens, where some module receives them, carries a `from`; any other carries and keeps nothing.
- Receivers are told in name order. One that throws is logged by name and error kind; the others are still told, and the login stays open.
- A held login's tokens are sealed with its IdP and local subject, under a carry of 256 random bits, kept for `transaction-lifetime` from the hold. If they cannot be kept, the callback is unavailable.
- The `from` names a deadline `transaction-lifetime` from the callback, before the kept tokens are gone, so `login-gates` refuses a resume from then on and no session opens without them.
- The kept tokens are taken once, in one rewrite, then removed after telling. They go only to a session of the subject that logged in, with their lifetime counted from the hand-over.

## Data
- Held login record, by its carry, in the transaction store: format 1, the sealed IdP, subject, hold time and tokens, and whether it was taken. One of another shape is none. Needs never to come back on failover (a taken one coming back could hand the tokens over twice).

## Depends on
- `kernel`, `login-gates`, `seal`, `session`; `upstreams` (the receivers, the tokens); `federation`'s section and store interface
