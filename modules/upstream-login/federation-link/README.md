# federation-link

## Responsibilities
- Links an upstream identity to the account a browser is logged in as, at its explicit request: the continuation named `link` of `federation`'s round trip.

## Not here
- The round trip: its start, callback, exchange and freshness (`federation`). The link records and their conflicts (`users`). Entering the session and its requirements (`session`). Handing the upstream tokens over (`upstream-handoff`).

## Offers
- Contributes the continuation `link` to `upstreams`' continuations; a start chooses it by `link=1` or `link=true` (`federation`'s route).
- Operator section: `step-up-page` (https; http only on a loopback host; none by default), as federation-grants-connect's setting of that name.
- A bridge of `federation` (`joins`): it comes wherever federation is composed. An app assembled by hand composes it beside federation; without it, a start asking a link is refused.
- Audit events for the subject the link started for, with `idp`, and `source` and `userAgent` when known: `federation.identity.linked`, or `federation.identity.link_refused` with `reason` (`conflict`, `session_short`, `session_closed_during_link`, `login_required`, or the round trip's `upstream_refused` and `exchange_failed`).
- Answer codes: `link_requires_trusted_origin` (403), `login_required` (401), a session requirement's answer with `requirement` (403), and with `step-up-page` also `page`: that page with `requirement` and `redirect_to`, the start's own URL on the public origin with `link=1`, never what the browser sent besides, `identity_conflict` (409), `temporarily_unavailable` (503). Success is a 302 to where the round trip lands.

## Invariants
- A start links only from this deployment's own page (`csrf`'s origin evidence), for a session entered at `credentials`. Another is logged `federation.link_start_rejected` (warn) with the IdP and the browser's `Sec-Fetch-Site`, printable and cut short.
- Without `mfa`, `credentials` asks a sign-in within `session-lifecycle.recent-authentication` (5 minutes by default), at the start and again at the callback: a link whose upstream step takes longer is refused.
- The callback links only while that session enters at `credentials` with the same subject, and the browser is in no other session; never by email.
- The session is checked before the link, right after it (before any token is handed over), and after the tokens' hand-off.
- A session closed, short of a requirement or logged in as someone else meanwhile is `401 login_required`, recorded `session_closed_during_link`; one that cannot be read is unavailable. Either way, what this request wrote is undone: the tokens it handed over are withdrawn, and a link it wrote is unlinked. A step of the undoing that is unavailable makes the answer unavailable, before any refusal is recorded.
- A hand-off that fails while the session still holds is unavailable, the link kept; one that fails as the session closes or cannot be read undoes the link, then is unavailable.
- An identity the account holds already is not linked again: no `linked` event is recorded for it (a refusal after may be), and it is never undone. One another account holds is `409 identity_conflict`.
- A link the configuration fixes is kept when undoing, logged `federation.link_kept_fixed` (warn).
- Undoing is best effort: a session closed after the last check keeps the link, and the unlink, having no generation, also removes the same link another request of that subject wrote meanwhile.
- A link creates no session and changes no session cookie.

## Depends on
- `upstreams` (the continuation), `url-setting`, `csrf` (origin evidence), `session` (entry), `users` (link, unlink), `upstream-handoff` (the hand-off), `audit`, `http`, `kernel`
