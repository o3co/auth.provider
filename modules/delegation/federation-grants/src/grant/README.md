# grant

Internal module of `federation-grants`: what a grant and a browser step are, and the judgments the other internal modules share.

## Responsibilities
- Reads and writes grant and step records, and seals a grant's credentials.
- Judges upstream tokens, a grant against its subject's boundaries and its end, and a client's permission and returns.

## Not here
- When records are written (`api`, `intents`, `refresh`), sealing itself (`seal`), the boundaries (`subject-revocation`).

## Offers
- `shared`, built by `sharedOver` from the build context: the public origin, `recordsWith`, `judgeWith` and `listingWith` over its contracts, once for the package. It refuses boot when connections lack the origin or their IdP's delegation. The other internal modules take the contracts they use from the build context; the package's module only declares the routes and contributions they fill.
- `recordsOver`: the records alone, for the follower, which `shared` cannot wait for.
- `recordsWith` (seal): `grantOf`, `stored`, `stepOf`, `storedStep`, `open`, `seal`.
- `judgeWith` (revocations, keep, longest life): `revoked`, `intentRevoked`, `endOf`.
- `listingWith` (listing, log): lists a grant under its subject, logging a failed write, or a listing the Store refused (its subject erased).
- `grantsEraser` (the three stores, the records' `grantOf`) → the eraser `federation-grants`, contributed to `erasure-extensions`' `erasers`: a subject's grants, pending pairs and listing erased through each store's `erase`, three reports, a window doing so for each subject; `migrate` reading a grant's subject from its record, a pending pair's from its key (`<client>\n<subject>`), anything else `unreadable`, and a listing none, as keyed by its subject; `erasable` only with the six ports.
- `portsRefused` (the grant, pending and subject stores) → why their ports cannot be used, or none: the six `erase` and `migrate` come together or none, a part refused at build in `sharedOver`; `portsOf` → the set, whole, or none.
- `credentialsFrom` (tokens, now, longest life, scopes shown, held refresh token, the access token kept) → held, or refused with why and any rotated refresh token. Its end is `upstreams`' `refreshedExpiry`: the access token kept, answered again, keeps the earlier of the two ends, its life counted from now.
- `connectionsIn` (settings, upstreams): a connection by name, and one with its IdP's delegation.
- `clientSection`, `permits`, `returnsTo`, `scopeTokens`, `within`, `withoutCredentials`, `secretFrom`.

## Invariants
- The package's resealer (as `federation-grants`) walks every grant, writing only over the credentials read and keeping the grant's lifetime, counting those no key opens. A refresh seals under the current key anyway.
- Each grant, pending pair and listing the stores write is for its subject; the stores' `erase` and `migrate` are optional in 0.20 and required in 0.22, all six or none.
- A refresh answering the access token kept counts its life from now: a back-off, as the next refresh waits half of what is left, so an upstream that keeps answering the same token is asked about five times before its end. Counted from its first obtaining, it would be asked on every request within `refresh-before` until the rotation budget ran out.
- A record of another shape is none; credentials open only under the grant they were sealed for.
- Each part of an upstream's tokens is read once; one that throws is none.
- A grant ends at the earlier of its own end and its activation plus the longest life allowed now, on `kernel`'s clock.
- A subject's boundary revokes a grant activated, and an intent begun, in or before its second, on the clocks of the hosts that wrote each, with nothing allowed for their skew: on a host whose clock runs ahead of the revoking one's, a grant or intent made just before the revocation can count as after it and outlive it.

## Data
- Grant format 1: client, subject, connection, status and reason, scopes shown, times, upstream account, current intent, sealed credentials, version, rotations of the window.
- Step format 1: kind (`link` or `question`), grant, intent, session, and whether it was taken. An upstream round trip's verifier and nonce are `upstream-round-trip`'s.

## Depends on
- `kernel`, `http` (the public origin), `seal`, `subject-revocation`, `clients`, `upstreams` (the connections' delegations); the package's store interfaces
