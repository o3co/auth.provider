# client-credentials

## Responsibilities
- Contributes the client credentials grant (RFC 6749 §4.4): a confidential client takes a token for itself, within its allowance.

## Not here
- Authenticating the client, the endpoint and its answers (`token-endpoint`). What a client may be issued (`client-allowance`). Issuing the token (`tokens`, through `grants`' `issue`).

## Offers
- Contribution to `grants`: `client_credentials` (`clientCredentialsGrantType`), reading no ambient credential, taking its audience from the request.
- `clientCredentials` (issuer) → the grant, for an assembly of one's own.

## Invariants
- Only a confidential client is served; a public one is `unauthorized_client`.
- The scope is the client's defaults when it asks none, never one outside its allowance (`invalid_scope`); the audience is within its allowed audiences, or the issuer when it has none.
- The token's subject and the client it is issued to are both the client; nothing is used up before issuing.

## Depends on
- `grants`, `client-allowance`, `issuer` (its URL), `kernel`
