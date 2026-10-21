# idp-github

## Responsibilities
- Contributes the IdP type `github` to `upstreams`: GitHub's OAuth, which is not OpenID Connect, reached through `outbound`.
- Builds the authorization request, exchanges the code, and reads the user from GitHub's API.

## Not here
- The login's round trip, its transaction, its state and PKCE values, and the local user (`federation`).
- Where requests may go (`outbound`).
- Refreshing tokens and ending the upstream session, which this type does not offer.

## Offers
- Composition definition only (the IdP type `github`)
- IdP settings (under `federation`'s `idps.<name>`): `client-id`, `client-secret` (both non-empty, well-formed text), `scopes` (default `read:user`), `authorization-endpoint`, `token-endpoint`, `api` (default GitHub's own; another for GitHub Enterprise), `issuer` (non-empty; default `https://github.com/login/oauth`)

## Invariants
- Every request goes through `outbound`, narrowed to the hosts of the token endpoint and the API, and sent for the endpoint the operator set (`internal`), so a GitHub Enterprise at a private address is reached where `outbound.internal-hosts` lists its host.
- Boot is refused, at its key, where `outbound`'s destination policy refuses the token endpoint or the API's user URL with that same narrowing, saying which of its keys to set (`outbound.refusals`); GitHub's own defaults are asked too.
- A callback whose `iss` is not the issuer is refused before its code is used.
- A callback without `iss` is taken, since GitHub may send none.
- The code goes to the token endpoint with its PKCE verifier and the client's secret in the form.
- A token answer is taken only as a 200 with a non-empty access token of type bearer, in any case.
- GitHub answers a refused code with 200 and an error, so that answer is refused.
- The access token goes only to the API's user URL, and is then dropped.
- The upstream subject is the user's numeric `id` in decimal digits, never the login name.
- The `id` must be a positive safe integer, or those digits without a leading zero.
- The login carries no login time and an empty amr, since GitHub says neither. So a `prompt=login` or `max_age` login through GitHub always gets `login_required`.
- `federation` gets `email`, `name` and `avatar_url` (as the picture) where they are text.
- The email is always unverified, since GitHub's user answer cannot say otherwise.
- An upstream that cannot be reached is unavailable.
- Anything else that fails refuses the login, without the library's or GitHub's text.

## Depends on
- `kernel`, `upstreams`, `upstream-client`, `outbound`, `outbound-policy`
