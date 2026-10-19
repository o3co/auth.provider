# device-grant

## Responsibilities
- Provides the OAuth 2.0 Device Authorization Grant (RFC 8628): device authorization, the verification interface the deployment's page calls, and the `device_code` grant.
- Decides when a device gets tokens: after a signed-in user approved its code, to the code's client, once.

## Not here
- Client authentication and OAuth error responses (`token-endpoint`). Session entry and its requirements (`session`). The verification page (the deployment's). Counting (`rate-limit`).

## Offers
- Route `POST /oauth/device_authorization`. It takes a form and authenticates the client as the token endpoint does (public clients too). It asks `grants`' target rule, as for a grant taking no audience, whether one may be asked, and answers its refusal.
  - Answers `device_code`, `user_code` (`XXXX-XXXX`), `verification_uri`, `verification_uri_complete` (when set), `expires_in` and `interval`.
- Route `POST /oauth/device/verification`, for the deployment's page. It takes a JSON body as `http` reads it, and answers JSON.
  - Fields: `action` (`lookup`, `approve` or `deny`) and `user_code`. A member that is not a string counts as absent.
  - `lookup` answers `client_id`, `scope` and `expires_at`. `approve` and `deny` answer `status` and `client_id`.
  - Errors: `invalid_request` (400), `login_required` (401), `step_up_required` (403), `access_denied` (403, a policy refusing the approval), `invalid_user_code` (404), `already_decided` (409), `expired_token` (410), `slow_down` (429, with `retry-after`), `temporarily_unavailable` (503, the route's declared answer, warned by `http` as `http.unavailable` with what and the route).
  - `step_up_required` passes the requirement's name and answer on unread.
- The `urn:ietf:params:oauth:grant-type:device_code` grant to `grants`: `authorization_pending`, `slow_down`, `access_denied`, `expired_token`, `invalid_grant`, or an access token.
- Audit events to `audit`, from the verification interface, with the subject and the request's `source` when `request-source` determined it, never a user or device code: declared in `./audit-events`, listed in the audit event reference.
- Contribution to `issuer`'s metadata: `device_authorization_endpoint`, absolute on `http`'s public origin, and left out without one.
- Store interfaces, which never see what a record holds: devices, by a name made from the device code (put, read, rewrite); user codes (the device's name, per code). Needs: no eviction, survives a crash, never rolled back by failover.
- Operator section (bounds, default; a time with its unit, in whole seconds): `verification-uri` (required; https, by `url-setting`), `complete-uri` (false), `code-lifetime` (30s–1h, 10m), `interval` (1s–1m, 5s), `attempts` (1–100, 5) per `attempts-window` (1m–1d, 5m), `requests` (1–100000, 60) per `window` (1s–1d, 1m).
- `./testing`: test configuration builders and the store contract test.

## Invariants
- Boot is refused unless a module records its tokens to the session that approved them (`grants`' `sessionIssuances`), so that a logout ends them.
- Device authorization is limited per source by `rate-limit`'s policy, before the client is authenticated.
- The client must be explicitly allowed this grant. `token-endpoint`'s allowance decides the scope there, and nothing widens it later.
- The device code is 32 random bytes. It is never kept; only its name is.
- The user code is 8 of 20 consonants (about 35 bits), drawn without bias, drawn again a few times when it meets one in use, and keys its index as is: its short lifetime and the attempt limit guard it.
- Input forgives case, spaces and hyphens only. Any other character is refused without asking the store.
- The verification interface declares `csrf`'s policy. Looking up and denying enter the session at level `none`; approving enters at `use`.
- Every action counts against the subject in `rate-limit`'s attempt limit. A count it cannot make is answered as unavailable.
- An approval is put to `tokens`' issuance policies with its session once counted and found, before it is kept; a refusal is `access_denied`.
- A code is decided once, by a rewrite from `pending`; a decision made first stands. An approval keeps the subject, the approval time, the session, its amr and its authentication time.
- A poll is one rewrite of the record it reads. Two polls at once issue once, carrying the approval's amr and authentication time (none where the session did not know it), if `tokens`' issuance policies allow, asked with the approving session before the poll takes the code.
  - Another client's poll writes nothing and is `invalid_grant`.
  - A poll before the interval is over is `slow_down`, and widens the interval by 5 seconds.
  - An approval or a denial is answered once, and the record is taken.
- A subject revoked since the approving session's authentication is `invalid_grant`, and so is an approving session that does not enter at use (closed, or short of a requirement), checked before the poll takes the code and again once the token is made, which is then never answered.
- The token is an access token to the approving subject, with the scope and audience decided at device authorization, ending no later than the approving session.
- A kept record is read only in the shape written here or the format before, with times a date can hold; any other, or one that throws, is no record.
- Times are on `kernel`'s clock. A decision or a poll reads it in the rewrite of the record, so a code that ends meanwhile is `expired_token`.
- A record is kept as long again past its end, so a late poll is told `expired_token`.
- Internal modules `authorization`, `verification` and `grant` each take their contracts from the build context; the package's module only declares.

## Depends on
- `kernel`, `audit`, `http`, `url-setting`, `request-source`, `clients`, `issuer`, `grants`, `token-endpoint`, `tokens`, `session`, `subject-revocation`, `rate-limit`, `csrf`

## Vocabulary
- device code: the code the device polls with. user code: the short code a user enters on another device.
- poll-too-soon: a device polled before its interval was over; the interval widens.
- attempts-exceeded: a subject tried more decisions at the verification interface than its limit allows. Both are answered as `slow_down`.
