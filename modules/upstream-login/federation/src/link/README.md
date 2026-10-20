# link

Internal module of `federation`: a round trip that links the upstream identity to the account the browser is logged in as.

## Responsibilities
- At the start, admits a link only from this deployment's own page and for a session entered at `credentials`, and records that session and its subject in the round trip.
- At the callback, links the upstream identity to that subject through `users`, and hands the upstream tokens to that session.

## Not here
- The round trip itself: its take (`upstream-round-trip`), the exchange and the freshness check (`round-trip`). The link records and their conflicts (`users`). Entering the session and its requirements (`session`).

## Offers
- `linkIn`: `linkWith` built from the build context.
- `linkWith` (`csrf`'s origin evidence, `session`'s entry, `users`' link and unlink, `audit`, `upstream-handoff`'s join, `kernel`'s log, the landing) → the round trip's link continuation.

## Invariants
- The callback links only while the recorded session enters at `credentials`, as its start did, with the recorded subject, and the browser carries no other session; else `401 login_required`, recorded with reason `login_required`, or `session_short` where the session is short of a requirement.
- An identity another account holds is `409 identity_conflict`. One the account holds already changes nothing and records nothing.
- A start a session requirement holds is `403` with the requirement's answer and its name (`requirement`). Without a requirement at `credentials` (no `mfa` composed), `session` asks a sign-in at a known time within 300 s, as `403` with requirement `session`.
- A start not shown to come from this origin is logged (`federation.link_start_rejected`, warn) with the IdP and the browser's `Sec-Fetch-Site`, printable and cut short.
- Records `federation.identity.linked`, or `link_refused` with the reason, for the recorded subject, by `round-trip`'s recorder (`idp`, and `source` and `userAgent` when known).
- A join that fails is unavailable (`503`): the link stays, the tokens given are undone (`upstream-handoff`).
- The session is read once more at `credentials` after the link and the join. Closed, short of a requirement or logged in as someone else: `401 login_required`, recorded `link_refused` with reason `session_closed_during_link`; unable to tell, unavailable.
- Either way, what this request wrote is undone: the join's tokens are withdrawn from each receiver given them, leaving any written since, and a link it wrote (not one held already) is unlinked; one the configuration fixes is kept, logged (`federation.link_kept_fixed`, warn).
- That amends is best effort: a session closed after the second read keeps the link, and the unlink has no generation, so it also removes the same link another request of that subject relied on meanwhile.

## Depends on
- `csrf` (origin evidence); `session` (entry); `users` (link, unlink); `audit`; `upstream-handoff` (join); `round-trip` (the continuation, the redirect, the landing); `http` (the JSON answer); `federation`'s section
