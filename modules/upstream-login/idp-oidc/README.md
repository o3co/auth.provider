# idp-oidc

## Responsibilities
- Contributes the IdP type `oidc` to `upstreams`: an upstream OpenID Connect provider, reached through `outbound`.
- At boot, reads the issuer's description (its OpenID Provider metadata) and checks that it names the issuer, or takes the three endpoints as the operator gives them.
- Builds the authorization request (code flow with PKCE, state and nonce).
- Exchanges the code, and checks the id_token it answers with.
- Hands the login's tokens over, and refreshes them.
- Builds the URL that ends the upstream session.
- Offers offline delegation: the authorization request, the code exchange and the refresh, for a delegation's scopes and resource.

## Not here
- The login's round trip, its transaction and the local user (`federation`). Where requests may go (`outbound`).

## Offers
- Composition definition only (the IdP type `oidc`)
- IdP settings (under `federation`'s `idps.<name>`): `issuer`, `client-id`, `client-secret` (both well-formed text), `token-auth` (`client_secret_basic` (default) or `client_secret_post`), `scopes` (must hold `openid`; default `openid`), `algorithms` (the asymmetric ones `external-jwt` knows; default RS256, ES256, EdDSA, one for each kind of key), `require-iss` (default false), `clock-skew` (0s–5m, default `30s`; times written with their unit, a bare number refused)
- IdP endpoint settings (in the same place): `discovery` (default true), `authorization-endpoint`, `token-endpoint`, `jwks-uri` (all three, only without discovery), `end-session-endpoint` (optional, only without discovery), `endpoint-hosts` (hosts besides the issuer's its endpoints may be on, read as `outbound` reads a host list: a host, or `.name` for the name and the names under it; default none)

## Invariants
- Every request to the upstream goes through `outbound`, narrowed to the issuer's host, the `endpoint-hosts` and the hosts of endpoints the operator gives, and sent for an operator's URL (`internal`): the issuer for all its description names (an endpoint on another origin, another port too, reaches public addresses only), each given endpoint for itself; the client's secret goes to no other host.
- An issuer's description that names an endpoint (its end of session included) on another host, as `outbound` matches hosts, refuses boot.
- An endpoint the browser goes to (authorization, end of session), described or given, holds only where `outbound.refusals`' `browsedRefusal` takes it for the issuer or the given endpoint: https, or plain http at a loopback name or a `plain-internal` origin; else boot is refused, at `issuer` or the key. Plain http there carries the user's password and the IdP's cookies in the clear between browser and IdP, outside any mesh.
- Boot is refused, at its key, on a URL this server sends to that `outbound`'s destination policy refuses with that same narrowing: the description's own URL (at `issuer`), or `token-endpoint` and `jwks-uri` without discovery; it says which of `outbound`'s keys to set (`outbound.refusals`).
- A description whose token endpoint or key set that policy refuses also refuses boot.
- A description's refusal, `outbound` refusing to fetch it included, is told at `issuer`, with its reason; one the policy gives names the endpoint and the policy's reason. A description answered other than `200`, or that cannot be read as one (no JSON object, not its shape), refuses boot at the IdP, in `federation`'s words, not under `issuer`.
- An answer naming another issuer in `iss` is refused before its code is used.
- An answer without `iss` is refused where the issuer's description offers `iss` or the operator requires it.
- Where neither requires `iss`, boot logs a warning naming the IdP (answers are then taken without `iss`).
- The id_token is checked by `external-jwt` with the issuer's key set at its `jwks_uri`, under `algorithms` and `clock-skew`, expecting the issuer and the client among its audiences. A key is read under one algorithm (`external-jwt`): with RS256 and PS256 both taken, one naming no `alg` is unused; an IdP signing with PS256 alone takes `["PS256"]`.
- An id_token that gives `at_hash` must give the access token's, by its signature's digest; one that does not refuses the exchange.
- Any reason `external-jwt` gives refuses the login.
- The id_token must name the client as `azp` where it names other audiences, or wherever it gives `azp`.
- The id_token must carry the login's nonce, a subject and a numeric issue time.
- The id_token must say no login time (`auth_time`) before 0 or past `kernel`'s clock by more than `clock-skew`.
- Says when the upstream logged the user in from the id_token's `auth_time`.
- Gives `federation` `clock-skew` as the upstream's clock allowance.
- Gives `federation` the profile in the checked id_token: `email`, `name` and `picture` where they are text. No other claim, and nothing from userinfo.
- The email is verified only where `email_verified` is the boolean `true`.
- When `external-jwt` has no key set to give, a callback is unavailable.
- The code goes with its PKCE verifier.
- The client's secret is sent as `token-auth` says.
- A token endpoint that does not answer 200 with an access token, its type and an id_token refuses the login.
- A token endpoint that cannot be reached is unavailable.
- The login hands on the access token, its type, refresh token, lifetime and scope (the asked scope where none is said), and the checked id_token.
- A refresh answers `invalid_grant` for a 400 saying so.
- A refresh answers a limit for a 429, with `retry-after` where it is whole seconds in digits.
- A refresh answers unavailable for a 5xx.
- A refresh never hands on an id_token, which it does not check.
- A delegation's start whose scopes lack `openid` is refused as a value, without throwing.
- A delegation's start with `offline_access` asks the user to consent.
- A delegation's exchange sends the delegation's resource with the code.
- A delegation's exchange checks the id_token as a login's does, and names the issuer.
- A delegation's answer that does not say its scope has the delegation's scopes.
- The session ends at the description's `end_session_endpoint` (or `end-session-endpoint`) with the id_token hint, return URI, state and client ID.
- Without an end of session endpoint, the upstream offers no end of session.

## Depends on
- `kernel`, `upstreams`, `upstream-client`, `outbound`, `outbound-policy`, `external-jwt`
