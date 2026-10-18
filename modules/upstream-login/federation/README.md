# federation

## Responsibilities
- Logs a browser in through an upstream IdP and hands the login to `login-gates`.
- Links an upstream identity to the account a browser is logged in as, at its explicit request (`link`).

## Not here
- What an IdP type, an upstream and a receiver are (`upstreams`).
- The link records and their conflicts (`users`).
- Where a login may return to (`login-gates`).
- Opening the session (`session`, through `login-gates`).

## Offers
- Composition definition: `GET /session/oauth/federation/<idp>` (start: `redirect_to`, `prompt` (only `login` is passed on), `max_age`, `link` (`1` or `true` links; any other value is a login)) and `…/<idp>/callback` (`code`, `state`, `iss`, `error`; by POST for an IdP that answers in a posted form, else GET; the other method is 405); starts and callbacks are limited per source
- Provides `upstreams`, as its default adapter.
- The operator section (its keys in the settings list).
- Store interface for transactions, its needs (survives failover) and contract test; test configuration builders and an IdP type for tests (`./testing`)
- Audit events for a callback that took its transaction, with `idp` and the source `request-source` determined: `federation.login.succeeded`, or `federation.login.held` when a gate held it, with the local subject; `federation.login.failed` with `reason` (`upstream_refused`, `exchange_failed`, `login_required`, `unknown_user`)
- For a link, `federation.identity.linked`, or `federation.identity.link_refused` with `reason` (`conflict` or one of the first three), for the subject it started for.
- No audit event comes before the take or records an unavailable answer, and none holds the upstream subject, tokens or text.
- Answer codes: `not_found` (404), `repeated_parameter`, `invalid_redirect`, `invalid_request`, `invalid_state`, `upstream_refused` (400), `unknown_user`, `login_required` (401), a gate's or a session requirement's answer, `link_requires_trusted_origin` (403), `identity_conflict` (409), `method_not_allowed` (405, with `allow`), `exchange_failed` (502), `temporarily_unavailable` (503)
- Success is a 302 to the return target or the landing; a held login is a 403 with the gate's answer and cookies.

## Invariants
- A login's state, nonce and PKCE verifier (S256) are kept server-side in its transaction for `transaction-lifetime`. Only a callback at the same IdP carrying its state takes it, once, before the code is exchanged; a callback from elsewhere spends nothing.
- The transaction is kept under a random cookie named per IdP. The cookie, state, nonce and PKCE verifier are 256 random bits each.
- The start refuses a return target `login-gates` does not allow (`invalid_redirect`) and a `max_age` that is not 1 to 9 digits. A repeated parameter is refused after the path and method.
- A start finding a transaction under its cookie is unavailable.
- The state is compared in constant time. No cookie, no state, or no transaction to take is `invalid_state`. From the take on, every answer clears the cookie, unavailable included.
- An `error` or no code is `upstream_refused`, with no exchange.
- A failed exchange is logged with the IdP and its kind only. An unavailable upstream is 503.
- A login reports the upstream's login time as when the user authenticated, on our clock (a time within the type's clock allowance before the start's second counts as that second), or that it is unknown.
- After `prompt=login` or a max age, a login counts only when the upstream says when the user logged in.
- Fresh enough: after `prompt=login`, the upstream's login time plus the type's clock allowance is not before the start's second; with a max age, it is within the max age of now.
- The local user is found only by the IdP's name and the upstream subject. An unknown identity is refused, and nothing is created.
- Only a start that asks links, from this deployment's own page (`csrf`'s origin evidence), for a session entered at `credentials`.
- Its callback links only while that session is open with the same subject and the browser is in no other session; never by email.
- A link creates no session and changes no session cookie.
- Without `mfa`, an open session of any age may link.
- A link whose tokens cannot be handed over is `503`, and one whose session closed or changed hands meanwhile `401`, the link kept.
- The login proves `fed` plus only the upstream amr values the operator maps (declared as provable). An upstream's text and tokens never reach the browser or the logs.
- Of what an upstream says of the user, only its profile's email, name and picture reach the session, as strings, under the IdP's source name (`loginSource.upstream`).
- Its email is verified only where the type says the upstream verified it in the type's own form; otherwise it is unverified.
- Groups and other claims never reach the session.
- A held login's tokens are kept for `transaction-lifetime` from the hold; if they cannot be kept, the callback is unavailable.
- A held login resumes within `transaction-lifetime` of the callback.
- An IdP's redirect URI is the public origin plus its callback path.
- Boot is refused for an unknown type, settings the type refuses, an upstream that does not match its settings (under the key and with the reason the type gives, where it gives them), or no public origin, one reason per issue, all at once.
- An IdP that answers in a posted form has a cross-site cookie, so only `__Host-` and Secure; it refuses boot where cookies cannot be secure.

## Data
- Transaction record, by its cookie. The store derives its name from the cookie and never keeps the cookie in clear.
- Held login record, in the transaction store. It must never come back on failover.

## Depends on
- `kernel`, `upstreams`, `audit`, `csrf` (origin evidence), `http`, `cookies`, `request-source`, `url-setting`, `login-attributes`, `login-gates`, `session`, `users`, `rate-limit`, `seal` (only with token receivers)

## Vocabulary
- transaction: one round trip, a login's or a link's, from its start to its callback, taken once.
