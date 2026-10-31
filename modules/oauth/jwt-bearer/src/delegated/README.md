# delegated

Internal module of `jwt-bearer`: an assertion of a delegated issuer, which another module checks by its own rules (`delegatedAssertions`).

## Responsibilities
- Reads what the delegate answers, and decides whether the client may present the assertion: the one it is for, and, if public, proving the key it names.
- Holds the client metadata section `jwt-bearer`.

## Not here
- Which issuers are delegated and to whom (`issuers`). The checks themselves, the account, and the record of assertions used up (the delegate's). Issuing the token (the package).

## Offers
- `sentIssuerOf` (assertion) → the `iss` as sent, unverified, where it is read as a JWT and names one as a string.
- `checkedBy` (delegate, assertion) → its answer, read at this boundary. The delegate's `spend` is read as a ledger's is, by the package's `spentAt`.
- `holds` (the request's binding, a digest) → whether the request proves by DPoP the key the digest names: `BASE64URL(SHA-256(jkt))`.
- Client metadata section `jwt-bearer`: `accept-unbound` (default false); `acceptsUnbound` (client).

## Invariants
- An assertion whose `iss` is a delegated issuer goes its delegate's way alone: the delegate's refusal is the grant's, never another way tried. Its audience is an app, never this server: not RFC 7523 §3. jwt-bearer reads neither its audience nor its `jti`.
- Any throw of the delegate but Unavailable, and any answer of no shape the contract gives, is Unavailable: no token. Only `spent` lets a token be issued. Nothing is used up before `spend`; a `spend` that throws or loses its answer after the delegate used the assertion up answers unavailable, and a retry may be `assertion replayed`.
- The delegate's `invalid` answers `untrusted signer`, as for an unknown signer. One for another client is `assertion is for another client`. One with less than a second left before its end, as a delegate may take one within its clock allowance, is `expired`: asked when the delegate answers and again just before the spend. A token whose end, cut to the assertion's, is less than a second off on the clock once it is issued is handed to no one, also `expired`; the assertion stays used up.
- A public client proves the key the assertion names (`the request does not prove the key the assertion names` otherwise). With `accept-unbound`, it may present one that names none without a key; one that names a key is proved still. `accept-unbound` is read for registered public clients only, and each such client is logged at boot where delegated issuers are set, and each assertion so taken, as `jwt-bearer.accept_unbound` (warn) with the client.
- A confidential client's digest is not read: its authentication stands in.
- Then as any assertion: the client's allowance, the audience asked, the `sessions` boundary at the made time the delegate tells, the issuance policies, and only then the delegate's `spend`; the token ends by the delegate's expiry.

## Depends on
- `clients` (the client section), `grants` (the binding), `kernel`, `users` (the subject's shape); the package's contract
