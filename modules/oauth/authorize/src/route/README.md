# route

Internal module of `authorize`: the endpoint's requests and answers.

## Responsibilities
- Reads a request's parameters, confirms the client and its redirect URI, hands the trusted request to `flow`, turns its decision into the answer, and records the decision to `audit`.

## Not here
- The route's declaration, its rate limit and the contributions (the package's module, which only assembles). What is decided for a trusted request (`flow`). Matching a redirect URI (`redirect-uris`).

## Offers
- `path`, and `endpointOver` (the build context) → the endpoint's URL on `http`'s public origin.
- `routeOver` (the build context; refuses to start without a public origin) → `routeWith` (the issuer's URL and the endpoint's, `clients`' lookup, `audit`'s recording, `flow`, the log) → the handler of both methods.

## Invariants
- Parameter lengths are capped (state 512, others 2048). Before the redirect URI is trusted, errors go out as `token-endpoint`'s OAuth error responses.
- Once it is trusted, a repeated or too long parameter is `invalid_request` (a repeated one the composed rule reads, as its `repeated` answers), and unavailable becomes the refusal `temporarily_unavailable`.
- Unavailable, before trust or after, leaves one warning `authorize.unavailable` with only what was unavailable and the route.
- What is recorded comes from the decision itself: the subject of a code, the reason of a refusal that carries one, and the refusing policy's name.

## Depends on
- `http` (the request and response types, no-store, the public origin); `request-source` (the source); `issuer` (its URL); `audit` (recording); `clients` (finding the client); `grants` (the composed rule); `token-endpoint` (OAuth error responses); `kernel` (the build context, unavailable); `flow`, `redirect-uris`; the package's metadata section
