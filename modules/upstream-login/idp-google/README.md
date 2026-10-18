# idp-google

## Responsibilities
- Contributes the IdP type `google` to `upstreams`: Google's OpenID Connect at fixed endpoints, reached through `outbound`.
- Builds the authorization request.
- Exchanges the code, and checks the id_token it answers with through `external-jwt`.
- Refreshes tokens.
- Builds the URL that ends the upstream session.

## Not here
- The login's round trip, its transaction, whether a login is fresh enough, and the local user (`federation`).
- Where requests may go (`outbound`). The rules of JWT checks and fetching key sets (`external-jwt`). Keeping upstream tokens.

## Offers
- Composition definition only (the IdP type `google`)
- IdP settings (under `federation`'s `idps.<name>`): `client-id`, `client-secret` (both well-formed text), `access` (`offline` (default) or `online`), `require-iss` (default true), `authorization-endpoint`, `token-endpoint`, `jwks-uri` (default Google's own), `clock-skew` (0s–5m, default `30s`), `end-session-endpoint` (optional), `hosted-domains` (optional, lowercase domains)

## Invariants
- Every request goes through `outbound`, narrowed to the one endpoint's host.
- The client's secret goes only to the token endpoint, as HTTP Basic.
- Boot is refused, at its key, where `outbound`'s destination policy refuses `token-endpoint` or `jwks-uri` with its host alone.
- Google's own default endpoints are put to that policy too.
- A callback carrying an `iss` other than exactly `https://accounts.google.com`, an empty one included, is refused before its code is used.
- A callback without `iss` is refused while `require-iss` holds.
- The id_token is checked with RS256 only, Google's issuer exactly, the client among its audiences, and `clock-skew`.
- With several audiences, the id_token's `azp` must be the client.
- With one audience, `azp` may name another client: Google names there another client of the same project that asked for the login (cross-client identity).
- The id_token must also carry the login's nonce, a non-empty `sub` and a numeric `iat`.
- Any reason `external-jwt` gives refuses the login.
- The upstream subject is `sub` as it is.
- The upstream amr is empty.
- With `hosted-domains`, an exchange is refused unless the checked id_token carries `hd` equal to one of them; neither the authorize request's `hd` hint nor the email's domain decides it. Every login and link goes through the exchange; this type offers no delegation.
- `federation` gets the profile in the checked id_token: `email`, `name` and `picture` where they are text. No other claim (`hd` included).
- The email is verified only where `email_verified` is the boolean `true`.
- The request asks for `openid email profile`: Google puts the email and `email_verified` in the id_token only for `email`, and the name and picture only for `profile`.
- The login time comes only from the checked id_token's `auth_time`; one that is no number, below 0, or past `kernel`'s clock beyond the allowance, refuses the login.
- `offline` asks for `access_type=offline` and `prompt=consent`.
- A browser's `prompt=login` and max age are passed on as `prompt` and `max_age`.
- A token answer is read by `upstream-client`'s reader (a lifetime is whole seconds from 0).
- A token answer without an id_token refuses the login.
- The login hands on the access token, its type, refresh token, lifetime and scope (the asked scope where none is said), and the checked id_token.
- A refresh answers `invalid_grant` for a 400 saying so.
- A refresh answers a limit for a 429, with `retry-after` where it is whole seconds in digits.
- A refresh answers unavailable for a 5xx.
- A refresh never hands on an id_token, which it does not check.
- The session ends at `end-session-endpoint` with the id_token hint, return URI and state.
- Without `end-session-endpoint`, the browser goes to the return URI, or to Google's logout page, with the state.
- An upstream that cannot be reached is unavailable.
- Anything else that fails refuses, without the library's or Google's text.

## Depends on
- `kernel`, `upstreams`, `upstream-client`, `outbound`, `external-jwt`
