# connect

Internal module of `federation-grants`: the browser half of a connection.

## Responsibilities
- Answers the link a client sends the user to, the question, the user's decision, and the upstream's callback, where a grant is activated.

## Not here
- The client routes (`api`), session entry (`session`), the CSRF policy (`csrf`, declared by the package), the upstream's requests (the IdP type).

## Offers
- `browser`, built by `connectOver` from the build context through `connectWith` (sessions, clients, users, upstreams, stores, `grant`'s parts, audit, settings, origin, runtime) → `connect`, `question`, `decide`, `callback`.

## Invariants
- Every step enters the session at `use` as the intent's subject; a short session is told whose it is at `none` before anything else.
- Only the subject's short session goes to the step-up page, told the requirement it falls short of, once per requirement and login; back still short of the same requirement in the same login, it is refused.
- Whether the link's client may still use the connection is told only to the subject's session, before any trip to raise it.
- The first session to take a question holds the intent; another browser starts again.
- A question and a state are each taken once; a state only at its connection, before the code is exchanged.
- The upstream start is built before the question is spent: a throw is `503` and keeps it; a refusal ends the intent as `grant_not_authorizable`.
- A failure after the state is spent ends the intent, is audited, and returns to the client only while it lists the URI.

## Depends on
- `http`, `request-source`, `session`, `clients`, `users`, `federation`, `audit`, `kernel`; `grant`, the package's store interfaces
