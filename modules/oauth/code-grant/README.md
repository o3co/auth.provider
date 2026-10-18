# code-grant

## Responsibilities
- Holds authorization codes and redeems them at the token endpoint (the `authorization_code` grant), adding the ID token and the contributed additions to the answer.
- Voids a code that comes again, or whose session ends midway: the tokens it gave are revoked, and failed revocations retried.

## Not here
- The decisions up to issuing a code (`authorize`). The token format and how tokens are revoked (`tokens`). What the ID token holds (the maker).

## Offers
- Code issuance, for `authorize` only: client, redirect URI, PKCE challenge, nonce, scope, audience, session handle, subject, optional acr met → code. It checks again the session is open with that subject, the client may use the grant with that scope and audience, and the challenge's shape; the authentication context comes from the session.
- The `authorization_code` grant (`codeGrantType`, taking its audience from the request) to `grants`' grant extension point, and the scope that asks for an ID token (the maker's, or none).
- Extension point: the ID token maker, declaring its scope (two or more refuse boot). It is told the subject, client, nonce, authentication time (and whether the session knew it), amr, the code's acr if any, its scope and the session's handle.
- Extension point: session redemptions, told the session's handle and the client of each code redeemed in a session.
- Extension point: additions, one per answer field (one on the answer's own fields refuses boot): redemption facts → value or none, and optionally a revocation by redemption name.
- Store interfaces, wired by the assembly, never shown what a record holds: codes by a name made from the code (put; rewrite from the current contents, answering before and after); the void list (add, done, go through in order).
- Operator section: `code-lifetime` (10s–10m, default `10m`), `sweep-interval` (retry of failed revocations, 1s–1h, default `30s`). Times are written with their unit; a bare number is refused.
- `./testing`: configuration builders, and the store interfaces' contract test for every implementation (records whole and once, changed only from what they hold, ended at exactly their lifetime; voids kept until done, refused when full; lost answers, failovers, restarts and memory pressure where the place has them).

## Invariants
- A code is used up before it is checked, by a version-compared rewrite, so two uses at once count as reuse. A wrong verifier, client or redirect URI uses it up; a malformed request does not. The verifier is compared in constant time.
- Every refused code is `invalid_grant` with the same description. A closed session is refused, and checked again after issuing: closed meanwhile, the code is voided.
- A redemption is told to the session redemptions after issuing, which has the token recorded to the code's session, and before that second check.
- The audience asked (`grants`' `target`, within the code's), then the issuance policies, are asked before the code is used up, only for its client, redirect URI and verifier (a refusal leaves it unused), and again when issuing (a refusal then leaves it used up, giving nothing). The access token and the additions carry the code's amr, authentication time (or that it is not known) and acr, from the code's session.
- A code that comes again is listed first, whatever it holds, then marked void. A listed code's token is revoked, then the additions' revocations run, then it leaves the list; each host retries every `sweep-interval`. One that gave nothing leaves once its record ends; one with no record is logged and removed.
- A record that vanished during a redemption is refused and never written back (the code would be unused again). A record of a format or shape not known is a code that cannot be used: refused (not unavailable), or logged and removed from the list.
- The code is voided when a session redemption, the ID token or an addition fails, however it fails. Issuing that fails leaves it used up, giving nothing.
- A configuration that cannot revoke access tokens refuses boot.
- Trade-offs: whoever holds a leaked code can revoke the legitimate tokens while the code lives; a client that resends a redemption by itself fails it.

## Data
- Codes: a record per code name until its expiry; one that gave a token, until that token's end plus 120 seconds for clock drift (`kernel`'s clock; syncing hosts is the deployment's). The void list: until each code is settled.
- Needs: no eviction (tokens to revoke would be lost), a crash survived, no rollback on failover (a used code would come back), names derived from the code.

## Depends on
- `kernel`, `session`, `clients`, `client-allowance`, `tokens`, `grants`, `issuer`, `sender-binding`

## Vocabulary
- Redemption facts: the redemption name, client, subject, scope, audience, session handle, authentication context, the code's acr if any, the issued access token (id, expiry, type; not the token) and the binding the issued tokens hold.
