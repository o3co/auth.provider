# rp-logout

## Responsibilities
- Ends a session at a client's request and tells the session's clients that it closed: the logout route (`ending`), the front-channel page (`page`) and back-channel notices (`notices`).
- Keeps which clients redeemed a code in each session, and the notices not yet delivered.
- Apart from `logout` (the browser's own logout): these need hints, keys, outbound requests and client records that the browser's logout does not.

## Not here
- Closing the session and its cookie (`session`, which the browser's `logout` uses too). Judging an ID token hint (`oidc`). The upstream's end of session (contributed at `upstreamEnds`).

## Offers
- Routes `GET` and `POST /oauth/logout` (`ending`).
- Extension point `upstreamEnds`: at most one; two or more refuse boot.
- Client metadata section `rp-logout` (`registration`).
- Contribution to `code-grant`'s session redemptions: keeps the client until the session ends, and at least `remember-for`.
- `session`'s participant `notices`: answers once each notice is kept, then tries each once.
- `issuer`'s metadata items: `end_session_endpoint` (on `http`'s public origin), and `frontchannel_logout_supported`, `frontchannel_logout_session_supported`, `backchannel_logout_supported` and `backchannel_logout_session_supported` (true).
- Audit events with the subject and `sid`, and `source` and `userAgent` when known: `logout.success`, `logout.cascade_failed` (with `store` `session`, the module whose close failed); `logout.close_pending` with `sid` and `source` only, declared exactly as `logout` declares it. All declared in `./audit-events`.
- Operator section: `remember-for` (1m–30d, default `1d`), `notify-within` (1m–7d, default `1d`), `sweep-interval` (1s–1h, default `1m`); times are written with their unit, a bare number refused.
- Store interfaces, which the assembly wires, each needing no eviction, a crash and a failover survived: the clients of each session (a keyed set with lifetimes, answering those pushed out); the notices not yet delivered (add, done, go through; one whose handling fails stays).
- `./testing`: a configuration builder, and the contract tests of both store interfaces.

## Invariants
- Reads `id_token_hint`, `post_logout_redirect_uri` and `state`, from the query on a `GET` and the form on a `POST` (no other body is taken); nothing else.
- No hint, or one naming no session, is `400 invalid_request`; one `oidc` refuses, or on a `GET` one issued more than 24 hours ago, is `400 invalid_token`; a hint that cannot be judged, or any other check that cannot tell, is `503`, logged as `rp-logout.unavailable` (warn) with what failed.
- `sid` is taken from outside only in a hint the provider signed, and only to close that session.
- The return is used only when it exactly matches one the hint's client registered; otherwise it is dropped and the logout goes on. `state` goes with it. A client record that cannot be read drops its return and frame, logged as `rp-logout.client_unavailable`.
- The session closes through `session`'s `close`, which clears the cookie only when it opens the same session. A close that throws is `503` with `logout.cascade_failed`; a session no longer open (closed, ended or gone) is `200 {"logged_out":true}`, with no event, its cookie still cleared.
- After a close, `logout.success` (and `logout.close_pending` first when pending), with the subject and `sid`. Then, in order: the front-channel page when the browser prefers HTML to JSON and a client can be framed; `303` to the upstream; `303` to the return; `200 {"logged_out":true}`.
- Every answer is `no-store` with `Pragma: no-cache`.
- Each host sweeps the kept notices every `sweep-interval`, logging how many it keeps; a session's close never waits for a client.
- A client the store pushes out of a session's set is logged.
- A return is one `authorize` lets a client register. A front-channel or back-channel URL is http or https, without userinfo, a fragment, spaces or controls; a front-channel one has no `iss` or `sid` in its query, whatever its case, `-` or `_`, and its origin is one of the client's redirect URIs' (`authorize`'s `redirectsAt`): checked at boot for a registered client, and before framing for any other, whose frame is left out, logged.
- A record whose section does not fit is refused whole (`clients`).
- Each frame's URL gets `iss`, and `sid` when its client asked for the session (OpenID Connect Front-Channel Logout 1.0 §2).
- A frame whose origin a Content-Security-Policy host source cannot name is left out, logged.
- It declares it loads only the frames' origins and its one script.
- Without a place to go next, the page has no script and stays.
- A notice names the client, the session's handle and subject, the time it is given up (`notify-within` on `kernel`'s clock) and its logout token's `jti`; past that time, it is dropped and logged. Fields it does not know are left unread; one that does not read is dropped and logged.
- The logout token is signed by `keys` under `logout+jwt`, with `iss`, `sub`, `aud` (the client), `iat`, `exp` 300 seconds on, the notice's `jti` (the same on every try, so a client can tell a repeat), the back-channel logout event, and `sid` unless the client said no (OpenID Connect Back-Channel Logout 1.0 §2.4).
- It is posted as a form through `outbound`, which follows no redirect. A 2xx settles it; 408, 429, 5xx or a failure to reach the client keeps it; a destination `outbound` refuses or any other status settles it, logged.
- A client gone or without a back-channel URL settles it.

## Depends on
- `audit`, `authorize`, `clients`, `code-grant`, `http`, `issuer`, `keys`, `oidc`, `outbound`, `request-source` (the source), `session`

## Vocabulary
- notice: one client to tell that a session closed, until it is given up.
