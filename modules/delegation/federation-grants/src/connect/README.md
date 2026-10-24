# connect

Internal module of `federation-grants`: the browser half of a connection.

## Responsibilities
- Answers the link a client sends the user to, the question, the user's decision, and the upstream's callback, where a grant is activated.

## Not here
- The client routes (`api`), session entry (`session`), the CSRF policy (`csrf`, declared by the package), the upstream's requests (the IdP type). Whose upstream account a callback reached, and the identity check (`upstream-account`).

## Offers
- `browser`, built by `connectOver` from the build context through `connectWith` (sessions, `upstream-account`'s check, upstreams, round trips, the package's `grantIntents`, settings, log) → `connect`, `question`, `decide`, `callback`. It reads and changes intents only through `grantIntents`, never the store interfaces.

## Invariants
- Every step enters the session at `use` as the intent's subject; a short session is told whose it is at `none` before anything else.
- A browser sent to the login page or the step-up page comes back to the connect it opened: the package contributes the connect's path to `login-gates`' return paths, so a login returns there on the public origin alone.
- Only the subject's short session goes to the step-up page, told the requirement it falls short of, once per requirement and login; back still short of the same requirement in the same login, it is refused.
- Whether the link's client may still use the connection is told only to the subject's session, before any trip to raise it.
- The first session to take a question holds the intent; another browser starts again.
- A question is taken once.
- The upstream round trip is `upstream-round-trip`'s, named `federation-grants.<connection>` and kept for the intent's time left; its callback takes it, only at its connection, before the code is exchanged.
- From the take on, every answer clears the round trip's cookie, unavailable and an unreadable round trip included; a callback that takes nothing is refused as expired.
- Two round trips of one connection begun in one browser leave only the later one's callback.
- The upstream start is built before the question is spent: a throw is `503` and keeps it; a refusal ends the intent as `grant_not_authorizable`.
- A failure after the round trip is taken ends the intent, is audited, and returns to the client only while it lists the URI.
- The upstream's tokens are judged before the session and revocations are checked again: tokens not to hold end the intent, whatever that check would find.
- An activation writes only over its own intent, unended and within its time as read after the exchange.
- An activation is audited once written; dropping the pending first-time intent after it only tidies: a failure is logged and passed, and the browser goes back.

## Depends on
- `http`, `request-source`, `session`, `upstream-account`, `upstreams` (the delegation), `upstream-round-trip` (round trips), `kernel`; the package's `grantIntents` (`intents`)
