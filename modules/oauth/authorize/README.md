# authorize

## Responsibilities
- Provides the authorization endpoint, decides whether to issue a code, and has `code-grant` issue the code. Adds `issuer`'s URL to the redirect as `iss`.
- Decides on the redirect URI, PKCE, scope, prompt, and `max_age`.
- Asks a fresh login through `reauth`'s re-authentication records, never values in the URL.

## Not here
- Code records and redemption, the ID token (`code-grant`). The rules of redirect URIs and the client's section holding them (`redirect-uris`). Session entry decisions (`session`). Re-authentication records, their lifetime and store (`reauth`). Consent records and the first-party decision (`consent`). The login and `consent` pages (the deployment owns them).

## Offers
- Route `/oauth/authorize` (GET; a POST is a `303` to the GET with the same parameters, which reads the session)
- Both methods take other sites' requests, with the reason declared: a request arrives as the client's navigation and only starts what the user's own login and consent complete.
- Contribution of the return path `/oauth/authorize` to `login-gates`
- Contribution to `issuer`'s metadata items: `authorization_endpoint` (on `http`'s public origin), `response_types_supported` (`code`), `code_challenge_methods_supported` (`S256`), `response_modes_supported` (`query`), `request_uri_parameter_supported` (`false`)
- Contribution of `redirect-uris`' client metadata section (`authorize`) to `clients`
- Operator section: `login-page` (the login page. The return URL is added as `redirect_to`), `step-up-page` (the page that raises authentication. Optional); both https URLs (http only on a loopback host) by `url-setting`'s part for configured URLs, `oidc-mode` (`oidc-required` or `dual`), `requests` (requests per source in each window, over both methods), `window`
- Audit events (to `audit`, declared in `./audit-events`):
  - `authorize.granted` when a code is given, with the subject, `client` and `response_type` `code`.
  - `authorize.rejected` on a refusal decided for the client or its consent, with no subject, and `client` and `reason`.
  - `reason` is `grant_type_not_allowed`, `scope_omitted_without_default`, `client_not_first_party`, `consent_required`, or an issuance policy's reason with `policy` its name.
  - `source` only when `request-source` determined it.
  - Never the code, `state`, the redirect URI or the scope.
  - Nothing for a malformed request, an unknown client or an unknown redirect URI.
  - Nothing for unavailable either: a warning naming only what and the route, `http.unavailable` before the redirect URI is confirmed, `authorize.unavailable` after.
- Test configuration builders (`./testing`)

## Invariants
- Requests are limited per source by `rate-limit`'s policy, declared on both routes and counted together; over it, `429`.
- The return destination from login, step-up and consent is built from the `http` public origin, not from request headers.
- A redirect URI is taken when it matches a registered one by `redirect-uris`' rule. PKCE is required of every client, by S256 only.
- Prompt words are `none`, `login`, `consent` and `select_account`, and `none` stands alone. Under `prompt=none` nothing is shown: a needed login, step-up or consent is refused (`login_required`, `interaction_required`, `consent_required`).
- `acr_values` counts only the acr `acr` knows; none known is `unmet_authentication_requirements`. `claims` not a JSON object, or naming the acr of `id_token` or `userinfo`, is `invalid_request`. The code carries the first asked acr the session meets; a session that falls short goes to the `step-up-page` once, and without one, or back unraised, gets `unmet_authentication_requirements`.
- Under `oidc-mode` `oidc-required`, a request whose own `scope` does not name `openid` is `invalid_scope`, even when the client's default scope holds it. Under `dual`, a request without `openid` gets the scope it asks or the client's default.
- A client that is not first-party, once logged in, is refused with `unauthorized_client` while `consent` is not `asking`. Next, before consent, `tokens`' issuance policies are asked for the code's access token (`authorization_code`, the session); a refusal is `access_denied` with the policy's description.
- A first-party client (by `consent`) is never asked for consent. Any other is asked when `consent`'s records do not cover the scope, or with `prompt=consent`; a denial comes back as `access_denied`.
- Until the client and redirect URI are confirmed, errors are JSON with no redirect (unavailable: the routes' declared `503` `temporarily_unavailable`). After that every answer, errors and unavailable included, is a redirect to the redirect URI carrying `state` (when given once and not too long) and `iss`.
- A fresh login that `prompt=login` or `max_age` demands counts only through a `reauth` record, made for the whole request when the browser is sent to log in and taken by that request. A session whose authentication time `session` answers as unknown meets neither, nor an essential `auth_time`, so a login is asked again.
- Back from its login (its record taken) with the authentication time still unknown, a request is refused with `login_required`.

## Depends on
- `kernel`, `http`, `request-source`, `url-setting`, `clients`, `redirect-uris`, `reauth`, `session`, `consent`, `code-grant`, `issuer`, `grants` (the audience rule), `token-endpoint` (error answers), `client-allowance`, `tokens`, `login-gates`, `acr`, `rate-limit`, `audit`
