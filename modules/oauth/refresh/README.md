# refresh

## Responsibilities
- Owns refresh tokens and their families: rotation on every use, reuse detection, family revocation, revoking each access token a family issued.
- Links families to sessions, and revokes a session's families when it closes.
- Ties an access token to its family, adopting a token issued from it, and starts families bound to no session.

## Not here
- The access token format and its revocation (`tokens`). Whether a client is allowed a grant (`client-allowance`). The session lifecycle (`session`).

## Offers
- Grant `refresh_token` for `grants`, taking its audience from the request; a `code-grant` addition `refresh_token`, for a client allowed the grant; taking it back revokes the family its redemption started, or marks that none may start.
- A `tokens` access condition: a token whose family has ended is revoked, before the sweep revokes it.
- A `token-control` revocable kind `refresh_token`: only its client revokes it, with its whole family, answered as written so it is audited; another client is answered the same.
- A participant for closing a session.
- `grants`' token tie `family`: a token's family, `ended` (`family has ended`) or held to its end; a token issued from it is adopted.
- Contract `lineage`: `start(...)` → a family's first refresh token, or nothing for a client not allowed to refresh.
- Operator section `refresh`, with `lifetime` and `sweep-interval` (each written with its unit, in whole seconds) and `bind-confidential-clients` (false, as 0.17); its keys are in the configuration reference.
- Audit event `refresh.family_revoked`, with the subject and the client, when a reuse revokes a family; never a token, its secret or the family's name: declared in `./audit-events`, listed in the audit event reference.
- Store interfaces: families, redemptions, token links, each session's families, each family's access tokens, the families to revoke; their needs (never evicted, survives a crash, never rolled back by failover), contract test and configuration builders (`./testing`).

## Invariants
- Only a family's current token is usable, and each use swaps it for a new one. Any other token of the family is reuse and revokes the family; so is the loser of two concurrent uses.
- A token with anything after it, another client's token, and one without the family's binding are refused without spending it.
- A family's end is fixed when it starts; no access token from it outlives it, nor the family's session, where it has one. Each one carries the amr, authentication time and acr the family started with; a time not known when it started is stated by none. None carries claims a grant added to the access token its family began with: a family keeps none.
- Scope narrows only within the original grant, for that round's access token, each value once; omitted or empty is all of it. The audience asked narrows that round alone, within the family's and the client's.
- Before rotating: the family's session, if any, enters at use (not closed, ended, or short of a requirement); the subject's authentication is past the revocation boundary; the client's allowance covers this round; `tokens`' issuance policies allow it, told the issuance continues a grant (`continuing`). A refusal leaves the token usable.
- A binding is attached to a public client's family, and to a confidential one's where set, only when it starts. Every refusal is the same `invalid_grant`; a store failure is unavailable, never a negative verdict.
- The `family` tie's join takes a token only into a live family and only if it ends by the family's end; any other is revoked. Boot is refused where access tokens cannot be revoked.
- Internal modules `grant` (the grant), `founding` (a family's beginning, the code addition among them), `lineage` (the contract and the access condition) and `settle` (the stores, revocation, the revocable kind and the participant) each take their contracts from the build context; the package's module only declares.

## Data
- Family records (the current secret's hash, client, subject, scope, audience, session, authentication context, binding, end; or a revoked mark), what each redemption left, and each access token's family. Every record outlives what it covers by one allowance, for hosts whose clocks lag.

## Depends on
- `kernel`, `tokens`, `grants`, `client-allowance`, `code-grant`, `token-control`, `session`, `session-participants`, `subject-revocation`, `clients`, `issuer`, `sender-binding`, `audit`

## Vocabulary
- family: the series of refresh tokens that starts from one code redemption or one `start`. reuse: a token arriving that is not the family's current token.
- revoker: what revokes a family and the access tokens it issued, and finishes a revocation left halfway.
