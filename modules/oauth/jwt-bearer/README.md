# jwt-bearer

## Responsibilities
- Contributes the grant by JWT assertion.
- Internal modules, each as its own card says: `issuers`, `assertion`, `delegated`, `conditions`, `policy`, `clientless`, `id-jag` and `granting`.

## Not here
- Client authentication (`token-endpoint`).

## Offers
- Composition definition (grant, taking its audience from the request, and identifying the client of a request naming none where an entry has a `client`, as `clientless` tells it), and its contract (`.`), naming the signing algorithms taken by default (`algorithms`, one for each kind of key) and every one there is to take (`takenAlgorithms`).
- Extension point `signerKeys`, one per issuer: the keys of the signer an assertion names (its subject and `kid`) with the algorithms they take, or none; it throws Unavailable when it cannot tell, and is asked anew for each assertion. One answering each signer's own keys alone declares `perSigner`.
- Extension point `linkedSubjects`: the subject a linked issuer's verified signer stands for, by the IdP name and the signer's subject, or none; it throws Unavailable when it cannot tell. Contract `linkedIssuers`: each linked issuer with its IdP name (`upstream`), for the module declaring the names.
- Store interface for spent assertions: save a name for a lifetime, answering `created` or `exists`. Needs: never evicted, survives a crash and a failover (losing one lets an assertion be reused). Its contract test (`./testing`).
- Extension point `jtiLedgers`, one per issuer: a ledger shared with whatever else accepts that issuer's assertions, using one up by its `jti` as sent (`first` or `replayed`), in place of the store; it throws Unavailable when it cannot tell. Its contract test and a ledger in memory (`./testing`).
- Extension point `delegatedAssertions`: a delegated issuer's assertions, checked and used up by another module by its own rules (`delegated`). Client metadata section `jwt-bearer` (`delegated`).
- Operator section (`jwtBearerConfig` in `./testing`):
  - `issuers`, the trusted issuers, each entry as the internal module `issuers` reads it. `delegated-issuers`, as `issuers` reads them.
  - `max-assertion-lifetime` (`1s` to `1d`, default `1h`): how far ahead its `exp` may be when taken, and its `exp` − `iat`, as `external-jwt` holds a longest lifetime. `clock-skew` (`0s` to `5m`, default `30s`). Each in whole seconds with its unit, narrowed by an entry alone.

## Invariants
- Issued tokens do not outlive the assertion's expiry: one with less than a second left when its `jti` would be used up is `expired`, the `jti` left unused, and a token with less than a second left once signed is refused by `tokens`, also `expired`.
- Boot is refused on an entry `issuers` cannot read as a trusted issuer, as its card says, each at its place (`jwt-bearer.issuers.<i>`), never by its value; on a linked issuer with no contribution at `linkedSubjects` (users is not composed), and on two or more, naming them.
- `as-is`: the token is for the signer's subject. `linked`: for the subject `linkedSubjects` resolves (`upstream`, the signer's subject) to, asked after the assertion is verified and before the client, the `sessions` boundary and the `jti`; none is a refusal (unknown subject) and leaves the assertion usable.
- A refusal's reason is told in this grant's own words. Keys or subjects that cannot be told make the grant unavailable, using up no `jti`.
- Usable only when the client explicitly allows it, and bound both ways to an entry's `client` (`clientless`) whether the request names it or none: once verified, an assertion for another client is `assertion is for another client`, told before its conditions are asked, using up no `jti`; a delegated issuer's too, its delegate never asked.
- The audience asked (`grants`' `target`, after the scope) narrows the token within what the client may be issued and its issuer's ceiling; it is asked before the `sessions` boundary and the `jti` is written, so a refusal leaves the assertion usable.
- An assertion made at or before its subject's `sessions` boundary, widened by the section's `clock-skew`, not an issuer's own, as an issuer's clock may run so far ahead, gets no token: it is made at its `iat`, never later than now, and one without `iat` counts as made before any boundary. Checked before its `jti` is spent.
- An assertion's `jti` is once only: spent in its issuer's ledger where one is contributed, else through the store interface, by a hash of the `iss` as sent and the `jti`, unless spent already. In the store, a self-issued signer's assertions are spent apart from its issuer's own; a ledger keeps them apart only where it is told the `iss`, and one that is not counts both as one, which refuses more and never lets a reuse through.
- A ledger is asked with the `iss` and `jti` as sent, the `exp`, and the time it must stay used until (`policy`'s, set by no setting). A throw, or an answer neither `first` nor `replayed`, is unavailable, issuing nothing; the store is never written or read for that issuer, so a ledger out never falls back to it. One whose answer is lost may stay used: the client signs another.
- The token is issued through `tokens`' issuance policies, without a session. They are asked before the `jti` is written, so a refusal leaves the assertion usable, and again when issuing.

## Data
- Spent assertions, through the store interface (a wiring keeps them) or an issuer's ledger, by name as the invariants say. The lifetime is a relative value, as the store judges it by its own clock: until `policy`'s time. Only well-formed `jti` strings (without lone surrogates) are accepted.

## Depends on
- `kernel`, `http` (the public origin), `grants`, `client-allowance`, `clients`, `token-endpoint`, `issuer`, `external-jwt`, `outbound`, `outbound-policy`, `keys`, `subject-revocation`, `sender-binding` (where an entry takes the ID-JAG profile), `resource-indicators` (the form of an ID-JAG's `resource`), and `users`, through its internal modules `assertion` and `delegated`
