# jwt-bearer

## Responsibilities
- Contributes the grant by JWT assertion.
- Its internal module `issuers` holds the list of trusted issuers and their signers; `assertion` checks an assertion, all but its single use; `delegated` takes a delegated issuer's, which another module checks.

## Not here
- Client authentication (`token-endpoint`).

## Offers
- Composition definition (grant, taking its audience from the request), and its contract (`.`).
- Extension point `signerKeys`, one per issuer: the keys of the signer an assertion names (its subject and `kid`) with the algorithms they take, or none; it throws Unavailable when it cannot tell, and is asked anew for each assertion.
- Extension point `linkedSubjects`: the subject a linked issuer's verified signer stands for, by the IdP name and the signer's subject, or none; it throws Unavailable when it cannot tell. Contract `linkedIssuers`: each linked issuer with its IdP name (`upstream`), for the module declaring the names.
- Store interface for spent assertions: save a name for a lifetime, answering `created` or `exists`. Needs: never evicted, survives a crash and a failover. Its contract test (`./testing`).
- Extension point `jtiLedgers`, one per issuer: a ledger shared with whatever else accepts that issuer's assertions, using one up by its `jti` as sent (`first` or `replayed`), in place of the store; it throws Unavailable when it cannot tell. Its contract test and a ledger in memory (`./testing`).
- Extension point `delegatedAssertions`: a delegated issuer's assertions, checked and used up by another module by its own rules (`delegated`). Client metadata section `jwt-bearer` (`delegated`).
- Operator section:
  - `issuers`, the trusted issuers, each entry as the internal module `issuers` reads it. `delegated-issuers`, as `issuers` reads them.
  - `max-assertion-lifetime` (`1s` to `1d`, default `1h`), `clock-skew` (`0s` to `5m`, default `30s`), each written with its unit in whole seconds.

## Invariants
- Issued tokens do not outlive the assertion's expiry.
- How a signer is read and its keys asked for, a trusted issuer's key set, and a delegated issuer's assertion, which goes its delegate's way alone (its audience an app, not RFC 7523 §3): as the internal modules `assertion`, `issuers` and `delegated` say.
- A trusted issuer's assertion is checked by `external-jwt` with the keys of the trusted issuer it names, under this section's policy: the algorithms of that issuer's keys (any the grant takes, for a key set), `clock-skew` as the allowance, `max-assertion-lifetime` as the longest lifetime. `aud` is `issuer`'s URL or the token endpoint's absolute URL as `token-endpoint` tells it; without one, the boot is refused. `sub` is a non-empty string.
- Boot logs `jwt-bearer.self_issued_signers` (info) with the places of the issuers taking self-issued signers, never a prefix.
- Boot is refused on an entry `issuers` cannot read as a trusted issuer, as its card says, each at its place (`jwt-bearer.issuers.<i>`), never by its value; on a linked issuer with no contribution at `linkedSubjects` (users is not composed), and on two or more, naming them.
- `as-is`: the token is for the signer's subject. `linked`: for the subject `linkedSubjects` resolves (`upstream`, the signer's subject) to, asked after the assertion is verified and before the client, the `sessions` boundary and the `jti`; none is a refusal (unknown subject) and leaves the assertion usable.
- A refusal's reason is told in this grant's own words. Keys or subjects that cannot be told make the grant unavailable, using up no `jti`.
- Usable only when the client explicitly allows it.
- The audience asked (`grants`' `target`, after the scope) narrows the token within what the client may be issued; it is asked before the `sessions` boundary and the `jti` is written, so a refusal leaves the assertion usable.
- An assertion made at or before its subject's `sessions` boundary, widened by `clock-skew` as its issuer's clock may run that far ahead, gets no token: it is made at its `iat`, never later than now, and one without `iat` counts as made before any boundary. Checked before its `jti` is spent.
- An assertion's `jti` is once only: spent in its issuer's ledger where one is contributed, else through the store interface, by a hash of the `iss` as sent and the `jti`, unless spent already. In the store, a self-issued signer's assertions are spent apart from its issuer's own; a ledger keeps them apart only where it is told the `iss`, and one that is not counts both as one, which refuses more and never lets a reuse through.
- A ledger is asked with the `iss` and `jti` as sent, the `exp`, and the time it must stay used until (`exp`, `clock-skew` and a minute). A throw, or an answer neither `first` nor `replayed`, is unavailable, issuing nothing; the store is never written or read for that issuer, so a ledger out never falls back to it. One whose answer is lost may stay used: the client signs another.
- The token is issued through `tokens`' issuance policies, without a session. They are asked before the `jti` is written, so a refusal leaves the assertion usable, and again when issuing.

## Data
- Spent assertions, through the store interface (a wiring keeps them) or an issuer's ledger, each by a hash of its `iss` as sent and `jti`. The lifetime is a relative value: the assertion's remaining lifetime plus the clock skew allowance and a margin (since the store judges it by its own clock). Only well-formed `jti` strings (without lone surrogates) are accepted.
- Needs: never evicted, survives a crash and a failover (losing one lets an assertion be reused).

## Depends on
- `kernel`, `grants`, `client-allowance`, `clients`, `token-endpoint`, `issuer`, `external-jwt`, `outbound`, `outbound-policy`, `keys`, `subject-revocation`, and `users`, through its internal modules `assertion` and `delegated`

## Vocabulary
- Trusted issuer: an issuer whose assertions are accepted.
