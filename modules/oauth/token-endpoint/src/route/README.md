# route

Internal module of `token-endpoint`: the handler of `POST /oauth/token`, from the request to the answer, and what a grant issues through.

## Responsibilities
- Reads a request's grant type and parameters, authenticates the client, checks the grant is allowed it and the binding, hands the grant its input, and answers what it gives, as the package's card says.
- Builds a grant's `admits` and `issue` over `tokens`, with the request's binding, telling the session issuances of a token issued from a session.

## Not here
- The built-in grant and the composed rule for the audience (`built-in`). The route's declaration, its limit and the metadata items (the package's module).

## Offers
- `tokenEndpoint` (clients, tokens, session issuances, binding readers, required bindings, grants by type, the audience rule, audit) → the handler and its answer to Unavailable; `tokenPath`.
- `grantInputOf` (what a grant is handed: its parameters' reader, the audience rule, `admits` and `issue`), `readerOf` and `mistypedRefusal`, which the package's `./testing` uses too.
- `issuanceFor` (tokens, grant type, binding, session issuances) → a grant's `admits` and `issue`; `refusedAnswer`, the one answer to a refused issuance.
- `answeredBody` (a grant's issued body as answered); `challenged` (a response with `WWW-Authenticate` challenges, which `authenticateClient` uses too).

## Invariants
- Records each answer but an unavailable one through the package's declared audit events, once the client is authenticated.

## Depends on
- `audit`, `client-allowance`, `clients`, `grants`, `http`, `request-source`, `sender-binding`, `tokens`; the package's contract and audit events.
