# grant

Internal module of `federation-grants`: what a grant and a browser step are, and the judgments the other internal modules share.

## Responsibilities
- Reads and writes grant and step records, and seals a grant's credentials.
- Judges upstream tokens, a grant against its subject's boundaries and its end, and a client's permission and returns.

## Not here
- When records are written (`api`, `connect`, `refresh`), sealing itself (`seal`), the boundaries (`subject-revocation`).

## Offers
- `shared`, built by `sharedOver` from the build context: the public origin, `recordsWith`, `judgeWith` and `listingWith` over its contracts, once for the package. It refuses boot when connections lack the origin, the page, or their IdP's delegation.
- `recordsOver`: the records alone, for the follower, which `shared` cannot wait for.
- `recordsWith` (seal): `grantOf`, `stored`, `stepOf`, `storedStep`, `open`, `seal`.
- `judgeWith` (revocations, keep, longest life, allowance): `revoked`, `intentRevoked`, `endOf`.
- `listingWith` (listing, log): lists a grant under its subject, logging a failed write.
- `credentialsFrom` (tokens, now, longest life, scopes shown, held refresh token) → held, or refused with why and any rotated refresh token.
- `connectionsIn` (settings, upstreams): a connection by name, and one with its IdP's delegation.
- `clientSection`, `permits`, `returnsTo`, `scopeTokens`, `within`, `withoutCredentials`, `secretFrom`, `retentionMs`.

## Invariants
- A record of another shape is none; credentials open only under the grant they were sealed for.
- Each part of an upstream's tokens is read once; one that throws is none.
- A grant ends at the earlier of its own end and its activation plus the longest life allowed now, on `kernel`'s clock.

## Data
- Grant format 1: client, subject, connection, status and reason, scopes shown, times, upstream account, current intent, sealed credentials, version, rotations of the window.
- Step format 1: kind (`link` or `question`), grant, intent, session, and whether it was taken. An upstream round trip's verifier and nonce are `upstream-round-trip`'s.

## Depends on
- `kernel`, `http` (the public origin), `seal`, `subject-revocation`, `clients`, `upstreams` (the connections' delegations); the package's store interfaces
