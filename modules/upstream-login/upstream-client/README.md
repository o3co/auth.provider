# upstream-client

## Responsibilities
- Gives IdP types what they share as OAuth clients of an upstream: the client's settings, the authorization request, the client's authentication, reading the upstream's answers, checking an OpenID Connect id_token (`src/id-token/`), and the end-session URL.
- Keeps library errors from a type's calls out of `federation`.

## Not here
- What a type asks of its upstream beyond these, and which of these rules it takes (the type). Making a start's state, nonce and challenge, and the login's round trip (`federation`). Checking a JWT's signature and times (`external-jwt`).

## Offers
- `credentialSetting`: a credential that is not blank. `clientSetting`: `client-id` and `client-secret`, which a type extends with its own settings. `endpointSetting`: an http or https URL, by `url-setting`'s `urlSetting`. `scopeSetting`: one scope, in RFC 6749's characters.
- `authorizationUrl` (the endpoint, the start, the client ID and scopes, the type's own parameters) → the URL.
- `basicAuthorization` (client ID, secret) → the HTTP Basic header value, each part form-urlencoded (RFC 6749 §2.3.1).
- `answerOf` (an answer as `outbound` reads JSON, a schema) → what the schema reads. `tokenAnswerOf` (an answer, the scope asked) → the upstream tokens, and the id_token apart.
- `refreshAnswerOf` (a refresh's answer, the scope asked, what is unavailable) → the refresh's outcome.
- `idTokenReaderOf` (`external-jwt`, the type's rules, a clock) → a reader: (id_token, the login's nonce) → the login (subject, login time, profile) and the checked claims, and `withUserinfo` (the upstream's UserInfo answer) → the login, its profile completed by it.
- `endSessionUrl` (the endpoint, the hint, return URI, state and client ID, the type's own parameters) → the URL.
- `guarded` (a type's call) → what it gives, or what it throws.

## Invariants
- A credential, the client's ID and secret among them, that is blank (empty or whitespace alone) or not well-formed text (half a surrogate pair) refuses boot; any other is taken as written.
- federation's parameters are set first: `response_type` `code`, the client ID, the redirect URI, the scopes joined by spaces, the state and the PKCE challenge with its method.
- A type's own parameter with the name of one of federation's is dropped; it never replaces it.
- Other parameters already in the endpoint's query stay.
- An answer that is no JSON object of a 200, or that the schema does not read, refuses as the upstream (`UpstreamRefused`).
- A token answer has a non-empty access token and type; a refresh token and id_token are non-empty text, a scope is text, and a lifetime is whole seconds from 0.
- A scope left out is the one asked; where the caller gives none to stand for it, the answer refuses.
- The id_token is never put among the tokens: the type checks it first.
- A refresh's answer is a limit for a 429, with `retry-after` only where it is digits; unavailable for a 5xx; `invalid_grant` for a 400 saying so; `interaction_required` for a 400 saying `interaction_required`, `login_required`, `consent_required` or `account_selection_required` (the user must act at the upstream first); else its tokens, never its id_token.
- An id_token holds only as `src/id-token/`'s card says.
- A UserInfo answer, and the profile it completes, hold only as `src/id-token/`'s card says.
- An end-session URL keeps the endpoint's query, then sets the parameters RP-Initiated Logout fixes (`id_token_hint`, `post_logout_redirect_uri`, `state`, `client_id`), each where given and non-empty, then the type's own.
- A type's own parameter with the name of a fixed one is dropped, given or not; it never replaces or places it.
- `guarded` lets `UpstreamRefused` and `Unavailable` out as they are; any other error becomes `UpstreamRefused`, without its text.

## Depends on
- `upstreams` (its contract's words), `url-setting` (the URL setting part), `kernel` (what is unavailable, the clock), `outbound` (its answers), `external-jwt` (the id_token's signature and times)

## Vocabulary
- client: this server, as an OAuth client registered at the upstream.
