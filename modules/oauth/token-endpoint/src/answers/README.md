# answers

Internal module of `token-endpoint`: the answers the OAuth endpoints share, an error response and a refused client authentication's.

## Responsibilities
- Shapes an OAuth error response, and the answer to a client authentication `clients` refuses.

## Not here
- Authenticating the client (`clients`). When an endpoint answers which (the endpoints: the package's `route`, and other modules through `authenticateClient`).

## Offers
- `oauthError`: an error response with the status, the code, an optional description, and the members `grants` lets a grant's refusal keep.
- `authenticateClient`, for other OAuth endpoints too: two methods at once or malformed credentials are `400 invalid_request`, others `401 invalid_client`. It records a refusal on the `audit` it is handed through `clients`' `recordRefusedAuthentication`.
- `refusedAuthenticationAnswer` (a refusal `clients` gives) → its answer. `challenged` (an answer, challenges) → the answer with them as its `WWW-Authenticate` (RFC 9110 §11.6.1), or as it is with none.

## Invariants
- `error_description` is printable ASCII but `"` and `\`, any other character shown as `?` (RFC 6749 §5.2). A member named as an error's or a success's is never taken from `members`, nor an `error_uri` that is no URI of printable characters.

## Depends on
- `audit` (the record a refusal is told on), `clients`, `grants` (the error codes), `http`.
