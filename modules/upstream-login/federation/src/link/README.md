# link

Internal module of `federation`: a round trip that links the upstream identity to the account the browser is logged in as.

## Responsibilities
- At the start, admits a link only from this deployment's own page and for a session entered at `credentials`, and records that session and its subject in the transaction.
- At the callback, links the upstream identity to that subject through `users`, and hands the upstream tokens to that session.

## Not here
- The round trip itself: the transaction, its take, the exchange and the freshness check (`round-trip`). The link records and their conflicts (`users`). Entering the session and its requirements (`session`).

## Offers
- `linkIn`: `linkWith` built from the build context.
- `linkWith` (`csrf`'s origin evidence, `session`'s entry, `users`' link, `audit`, `handoff`'s join, `kernel`'s log, the landing) → the round trip's link continuation.

## Invariants
- The callback links only while the recorded session enters at `use` with the recorded subject, and the browser carries no other session; else `401 login_required`, recorded with reason `login_required`, or `session_short` where the session is short of a requirement.
- An identity another account holds is `409 identity_conflict`. One the account holds already changes nothing and records nothing.
- A start a session requirement holds is `403` with the requirement's answer and its name (`requirement`). Without a requirement at `credentials` (no `mfa` composed), `session` asks a sign-in at a known time within 300 s, as `403` with requirement `session`.
- A start not shown to come from this origin is logged (`federation.link_start_rejected`, warn) with the IdP and the browser's `Sec-Fetch-Site`, printable and cut short.
- Records `federation.identity.linked`, or `link_refused` with the reason, for the recorded subject, by `round-trip`'s recorder (`idp`, and `source` and `userAgent` when known).
- A join that fails is unavailable (`503`): the link stays, the tokens given are undone (`handoff`).
- A session read again after its tokens joined it: closed, short of a requirement or logged in as someone else, `401 login_required`, recording nothing more; unable to tell, unavailable. Either way the link stays and the join's tokens are withdrawn from each receiver given them, leaving any written since.

## Depends on
- `csrf` (origin evidence); `session` (entry); `users` (link); `audit`; `handoff` (join); `round-trip` (the continuation, the redirect, the landing); `http` (the JSON answer); `federation`'s section
