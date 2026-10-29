# rp-logout

## Responsibilities
- Ends a session at a client's request and tells the session's clients that it closed: the logout route (`ending`), a person's confirmation where no hint names the session (`confirm`), the close both share (`closing`), the pages it ends on (`page`) and back-channel notices (`notices`).
- Keeps which clients redeemed a code in each session, and the notices not yet delivered.
- Apart from `logout` (the browser's own logout): these need hints, keys, outbound requests and client records that the browser's logout does not.

## Not here
- Closing the session and its cookie (`session`, which the browser's `logout` uses too). Judging an ID token hint (`oidc`). The upstream's end of session (contributed at `upstreamEnds`).

## Offers
- Routes `GET` and `POST /oauth/logout` (`ending`), both declared to take requests from other sites, and the GET to change state (no HEAD).
- Routes `GET` and `POST /oauth/logout/confirm` (`confirm`): the GET changes nothing; the POST takes a form under `csrf`'s policy, closing only the requester's own session; both share the logout's per-source budget, as each may sign a confirmation.
- Extension point `upstreamEnds`: at most one; two or more refuse boot.
- Client metadata section `rp-logout` (`registration`).
- Contribution to `code-grant`'s session redemptions (`redemptions`): keeps the client until the session ends, and at least `remember-for`.
- `session-participants`' participant `notices`: answers once each notice is kept, then tries each once.
- `issuer`'s metadata items: `end_session_endpoint` (on the origin `issuer` names its endpoints on, `endpointOrigin`: the public origin wherever one is written), and `frontchannel_logout_supported`, `frontchannel_logout_session_supported`, `backchannel_logout_supported` and `backchannel_logout_session_supported` (true).
- Audit events with the subject and `sid`, and `source` and `userAgent` when known: `logout.success`, `logout.cascade_failed` (with `store` `session`, the module whose close failed); `logout.close_pending` with `sid` and `source` only, declared exactly as `logout` declares it. All declared in `./audit-events`.
- Operator section: `remember-for` (1m–30d, default `1d`), `notify-within` (1m–7d, default `1d`), `sweep-interval` (1s–1h, default `1m`), `requests` (logout requests per source in each `window`, a GET and a POST together, before any hint is checked; 1–100000, default 60) and `window` (1s–1d, default `1m`); times are written with their unit, a bare number refused.
- Store interfaces, which the assembly wires, each needing no eviction, a crash and a failover survived: the clients of each session (a keyed set with lifetimes, answering those pushed out); the notices not yet delivered (add, done, go through; one whose handling fails stays).
- `./testing`: a configuration builder, and the contract tests of both store interfaces.

## Invariants
- What a logout request is read for, and each refusal before its close: `ending`'s card.
- The session closes through `session`'s `close`, which clears the cookie only when it opens the same session. A session closed before, or gone, is `200 {"logged_out":true}`, with no event, its cookie still cleared; one whose record the close found open, even past its lifetime or short of a requirement, is logged out.
- A close that is unavailable is `503` with `logout.cascade_failed`; any other error it throws is passed on, a mistake and no outage, so `http` answers it `500`.
- A close left pending records `logout.close_pending` and answers `503 temporarily_unavailable`, clearing the cookie, as `logout` does, however often it is sent again: its tokens live until the close is swept, so it is no logout yet.
- After a close, `logout.success`, with the subject and `sid`. Then, in order: the front-channel page when the browser prefers HTML to JSON and a client can be framed; `303` to the upstream; `303` to the return; `200 {"logged_out":true}`.
- Every answer is `no-store` with `Pragma: no-cache`.
- Each host sweeps the kept notices every `sweep-interval`, logging how many it keeps; a notice whose try failed is not tried again until a `sweep-interval` after it was last due, or made, whichever host tried it, a late sweep trying it at once (Back-Channel Logout 1.0 §2.5); a session's close never waits for a client.
- A client the store pushes out of a session's set is logged.
- Returns and channel URLs are as `registration` judges them; a registered client's back channel that `outbound`'s policy refuses refuses boot.
- A record whose section does not fit is refused whole (`clients`).
- Each frame's URL gets `iss`, and `sid` when its client asked for the session (OpenID Connect Front-Channel Logout 1.0 §2).
- A frame whose origin a Content-Security-Policy host source cannot name is left out, logged.
- It declares it loads only the frames' origins and its one script.
- Without a place to go next, the page has no script and stays.
- A notice names the client, the session's handle and subject, the time it is given up (`notify-within` on `kernel`'s clock), its logout token's `jti` and, once a try failed, the time before which it is not tried again; past that time, it is dropped and logged. Fields it does not know are left unread; one that does not read is dropped and logged.
- The logout token is signed by `keys` under `logout+jwt`, so with the algorithm of the client's ID tokens, which `oidc` holds to the one `keys` signs with (OpenID Connect Back-Channel Logout 1.0 §2.6); with `iss`, `sub`, `aud` (the client), `iat`, `exp` 300 seconds on, the notice's `jti` (the same on every try, so a client can tell a repeat), the back-channel logout event, and `sid` unless the client said no (OpenID Connect Back-Channel Logout 1.0 §2.4).
- It is posted as a form through `outbound`, which follows no redirect. A 2xx settles it; 408, 429, 5xx or a failure to reach the client keeps it; a destination `outbound` refuses or any other status settles it, logged.
- A client gone or without a back-channel URL settles it.

## Depends on
- `audit`, `clients`, `code-grant`, `csrf`, `http`, `issuer`, `kernel`, `keys`, `oidc`, `outbound`, `outbound-policy`, `rate-limit`, `redirect-uris`, `request-source` (the source), `session`, `session-participants`

## Vocabulary
- notice: one client to tell that a session closed, until it is given up.
