# idp-apple

## Responsibilities
- Contributes the IdP type `apple` to `upstreams`: Sign in with Apple, answering in a posted form, reached through `outbound`.
- Builds the authorization request.
- Exchanges the code, and checks the id_token it answers with through `external-jwt`.
- Refreshes tokens.
- Sends the client's secret Apple asks for: a fixed one, or one the team's key signs (internal module `client-secret`).
- Checks at boot that the callback is one Apple takes.

## Not here
- The login's round trip, its transaction, the posted form and its cookie, whether a login is fresh enough, and the local user (`federation`).
- Where requests may go (`outbound`). The rules of JWT checks and fetching key sets (`external-jwt`). Keeping upstream tokens.

## Offers
- Composition definition only (the IdP type `apple`, answering by `form_post`)
- IdP settings (under `federation`'s `idps.<name>`): `client-id` (the Services ID), `client-secret`, `team-id`, `key-id`, `private-key` (PKCS8 PEM; all five well-formed text), `secret-lifetime` (1m–15777000s, default `5m`), `scopes` (of `name` and `email`; default `email`), `authorization-endpoint`, `token-endpoint`, `jwks-uri` (default Apple's own), `clock-skew` (0s–5m, default `30s`), `end-session-endpoint` (optional)

## Invariants
- Boot is refused for a callback that is not https or is on loopback (`localhost`, 127.0.0.0/8, `[::1]`).
- Boot is refused for a key that is no P-256 key in PKCS8.
- Boot refusals name no key or secret.
- Boot is refused unless exactly one of `client-secret` and the three signing settings (all of them) is given.
- The callback checked at boot is the one sent, both in the authorization request and in the exchange.
- The authorization request asks for `response_mode=form_post`, with PKCE, state and nonce.
- A browser's `prompt` and max age are not sent, as Apple takes neither.
- A step-up through Apple asks Apple for no new login, and is judged only by the login time Apple's id_token says, which may predate the round trip; without one, a login asking `prompt=login` or a max age is refused (`login_required`).
- A callback carrying an `iss` other than exactly `https://appleid.apple.com` is refused before its code is used.
- A callback carrying no `iss` is taken, as Apple sends none.
- Every request goes through `outbound`, narrowed to the one endpoint's host.
- The client's secret goes only to the token endpoint, in the form.
- The client's secret is never made for the authorization request.
- Boot is refused, at its key, where `outbound`'s destination policy refuses `token-endpoint` or `jwks-uri` with its host alone.
- Apple's own default endpoints are put to that policy too.
- A signed secret lives `secret-lifetime`, on `kernel`'s clock.
- The id_token is checked with RS256 only, Apple's issuer exactly, the client among its audiences, and `clock-skew`.
- The id_token's `azp`, which several audiences need, must be the client.
- The id_token must also carry the login's nonce, a non-empty `sub` and a numeric `iat`.
- Any reason `external-jwt` gives refuses the login.
- The upstream subject is `sub` as it is.
- Nothing else the callback carries, the user's name included, is read.
- The upstream amr is empty.
- `federation` gets the profile in the checked id_token: `email`, `name` and `picture` where they are text (Apple sends the email alone). No other claim (`is_private_email` included).
- The email is verified only where `email_verified` is `true`, as a boolean or as text.
- The login time comes only from the checked id_token's `auth_time`; one that is no number, below 0, or past `kernel`'s clock beyond the allowance, refuses the login.
- A token answer without an id_token refuses the login.
- The login hands on the access token, its type, refresh token, lifetime and scope (the asked scope where none is said), and the checked id_token.
- A refresh answers `invalid_grant` for a 400 saying so.
- A refresh answers a limit for a 429, with `retry-after` where it is whole seconds in digits.
- A refresh answers unavailable for a 5xx.
- A refresh never hands on an id_token, which it does not check.
- The upstream session can be ended only where `end-session-endpoint` is given, with the id_token hint, return URI and state.
- An upstream that cannot be reached is unavailable.
- Anything else that fails refuses, without the library's or Apple's text.

## Depends on
- `kernel`, `upstreams`, `upstream-client`, `outbound`, `external-jwt`
