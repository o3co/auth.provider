# route

Internal module of `token-endpoint`: the handler of `POST /oauth/token`, from the request to the answer, and what a grant issues through.

## Responsibilities
- Reads a request's grant type and parameters, authenticates the client, or has a grant identify the client of a request naming none, checks the grant is allowed it and the binding, hands the grant its input, and answers what it gives, as the package's card says.
- Builds a grant's `admits` and `issue` over `tokens`, with the request's binding, telling the session issuances of a token issued from a session.

## Not here
- The composed rule for the audience (`built-in`). Authenticating the client and the shapes of an error answer (`answers`). Taking the contracts below from the assembly (`endpoint-in`). The route's declaration, its limit and the metadata items (the package's module).

## Offers
- `tokenEndpoint` (clients, tokens, session issuances, binding readers, required bindings, grants by type, the audience rule, audit) → the handler and its answer to Unavailable; `tokenPath`.
- `grantInputOf` (what a grant is handed: its parameters' reader, the audience rule, `admits` and `issue`), `readerOf` and `mistypedRefusal`, which the internal module `caller` uses too.
- `issuanceFor` (tokens, grant type, binding, session issuances, a sink for the names of added claims) → a grant's `admits` and `issue`, which tells the sink the names `tokens` answers for each token issued, never the grant read again; `refusedAnswer`, the one answer to a refused issuance.
- `answeredBody` (a grant's issued body as answered).
- A refused authentication is answered as `authenticateClient` answers it (`refusedAuthenticationAnswer`, the one mapping), and recorded only where no grant identifies the client.

## Invariants
- Records each answer but an unavailable one through the package's declared audit events, once the client is authenticated, or once a request goes to a grant that identifies its client (with `identified`, and `client` once known).

## Depends on
- `audit`, `client-allowance`, `clients`, `grants`, `http`, `request-source`, `sender-binding`, `tokens`; the package's contract and audit events; `answers` (client authentication, error answers and challenges); `identified` (the client a grant identifies).
