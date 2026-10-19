# jwt-bearer

## Responsibilities
- Contributes the grant by JWT assertion. Holds the list of trusted issuers.

## Not here
- Client authentication (`token-endpoint`).

## Offers
- Composition definition (grant, taking its audience from the request), and its contract (`.`).
- Extension point `signerKeys`, one per issuer: the keys of the signer an assertion names (its `sub` and `kid`) with the algorithms they take, or none; it throws Unavailable when it cannot tell, and is asked anew for each assertion.
- Extension point `linkedSubjects`: the subject a linked issuer's verified signer stands for, by the IdP name and the `sub`, or none; it throws Unavailable when it cannot tell. Contract `linkedIssuers`: each linked issuer with its IdP name (`upstream`), for the module declaring the names.
- Store interface for spent assertions: save a name for a lifetime, answering `created` or `exists`. Needs: never evicted, survives a crash and a failover. Its contract test (`./testing`).
- Operator section:
  - `issuers`, a list of `issuer` with `keys` (`kid`, `alg`, `public-key` (SPKI PEM; a private key refuses boot)), `jwks-uri` (where its key set is, at https on the issuer's host), or neither, its keys then contributed.
  - Each issuer's `subject` (`as-is` or `linked`, required), `upstream` (the IdP name its signers are known by, with `linked` only) and `subject-is-key-thumbprint` (default false).
  - `max-assertion-lifetime` (`1s` to `1d`, default `1h`), `clock-skew` (`0s` to `5m`, default `30s`), each written with its unit in whole seconds.

## Invariants
- Issued tokens do not outlive the assertion's expiry.
- A `kid` an assertion names is text of 1 to 256 well-formed characters, or the assertion is malformed, before any key is asked for.
- The assertion is checked by `external-jwt` with the keys of the trusted issuer it names, under this section's policy: the algorithms of that issuer's keys (any the grant takes, for a key set), `clock-skew` as the allowance, `max-assertion-lifetime` as the longest lifetime. `aud` is `issuer`'s URL or the token endpoint's absolute URL as `token-endpoint` tells it; without one, the boot is refused. `sub` is a non-empty string.
- A key set is fetched only at https from its issuer's host; a `jwks-uri` not at https or on another host, or with an issuer that is no URL, refuses the boot. While no key set can be had, the grant is unavailable.
- Boot is refused on an issuer with keys both written and contributed, or neither; on `upstream` without `linked`, or `linked` without it; on a linked issuer with no contribution at `linkedSubjects` (users is not composed), and on two or more, naming them; on `subject-is-key-thumbprint` with a key set, which cannot tell which key signed; and on an issuer without `subject`.
- Boot is refused on an issuer named twice in `issuers`, and on keys contributed for an issuer `issuers` does not name.
- The signer is read before anything is verified: a `sub` that is no well-formed subject, or no thumbprint where `subject-is-key-thumbprint` asks one, is refused before its keys are asked for. With thumbprints, only the key whose thumbprint is the `sub` verifies it; a contributed key is verified with the `sub` it was asked for.
- An unknown signer, a key that does not fit and a signature that does not match get the same answer.
- `as-is`: the token is for the `sub`. `linked`: for the subject `linkedSubjects` resolves (`upstream`, `sub`) to, asked after the assertion is verified and before the client, the `sessions` boundary and the `jti`; none is a refusal (unknown subject) and leaves the assertion usable.
- A refusal's reason is told in this grant's own words. Keys or subjects that cannot be told make the grant unavailable, using up no `jti`.
- A signer's `sub` is a subject only as OpenID Connect Core bounds one: 1 to 255 ASCII characters.
- Usable only when the client explicitly allows it.
- The audience asked (`grants`' `target`, after the scope) narrows the token within what the client may be issued; it is asked before the `sessions` boundary and the `jti` is written, so a refusal leaves the assertion usable.
- An assertion made at or before its subject's `sessions` boundary, widened by `clock-skew` as its issuer's clock may run that far ahead, gets no token: it is made at its `iat`, never later than now, and one without `iat` counts as made before any boundary. Checked before its `jti` is spent.
- An assertion's `jti` is once only: spent through the store interface, by a hash of the issuer and the `jti`, unless spent already.
- The token is issued through `tokens`' issuance policies, without a session. They are asked before the `jti` is written, so a refusal leaves the assertion usable, and again when issuing.

## Data
- Spent assertions, through the store interface (a wiring keeps them), each by a hash of its issuer and `jti`. The lifetime is a relative value: the assertion's remaining lifetime plus the clock skew allowance and a margin (since the store judges it by its own clock). Only well-formed `jti` strings (without lone surrogates) are accepted.
- Needs: never evicted, survives a crash and a failover (losing one lets an assertion be reused).

## Depends on
- `kernel`, `grants`, `token-endpoint`, `issuer`, `external-jwt`, `outbound`, `keys`, `subject-revocation`

## Vocabulary
- Trusted issuer: an issuer whose assertions are accepted.
