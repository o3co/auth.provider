# jwt-bearer

## Responsibilities
- Contributes the grant by JWT assertion. Holds the list of trusted issuers.

## Not here
- Client authentication (`token-endpoint`).

## Offers
- Composition definition only (grant, taking its audience from the request)
- Operator section: `issuers` (list of `issuer` and either `keys` (`kid`, `alg`, `public-key` (SPKI PEM; a private key refuses boot)) or `jwks-uri` (where its key set is, at https on the issuer's host)), `max-assertion-lifetime` (`1s` to `1d`, default `1h`), `clock-skew` (`0s` to `5m`, default `30s`), each written with its unit in whole seconds

## Invariants
- Issued tokens do not outlive the assertion's expiry.
- The assertion is checked by `external-jwt` with the keys of the trusted issuer it names, under this section's policy: the algorithms of that issuer's keys (any the grant takes, for a key set), `clock-skew` as the allowance, `max-assertion-lifetime` as the longest lifetime. `aud` is `issuer`'s URL or the token endpoint's absolute URL as `token-endpoint` tells it; without one, the boot is refused. `sub` is a non-empty string.
- A key set is fetched only at https from its issuer's host; a `jwks-uri` not at https or on another host, or with an issuer that is no URL, refuses the boot. While no key set can be had, the grant is unavailable.
- A refusal's reason is told in this grant's own words.
- Usable only when the client explicitly allows it.
- The audience asked (`grants`' `target`, after the scope) narrows the token within what the client may be issued; it is asked before the `sessions` boundary and the `jti` is written, so a refusal leaves the assertion usable.
- An assertion made at or before its subject's `sessions` boundary gets no token: it is made at its `iat`, never later than now, and one without `iat` counts as made before any boundary. Checked before its `jti` is spent.
- An assertion's `jti` is once only (written if absent from the store).
- The token is issued through `tokens`' issuance policies, without a session. They are asked before the `jti` is written, so a refusal leaves the assertion usable, and again when issuing.

## Data
- Space: assertion `jti`. Partition per trusted issuer. The expiry is a relative value: the assertion's remaining lifetime plus the clock skew allowance and a margin (since the store judges it by its own clock). Only well-formed `jti` strings (without lone surrogates) are accepted.
- Guarantees: no eviction, durable, replicated (losing it lets an assertion be reused).

## Depends on
- `kernel`, `grants`, `token-endpoint`, `issuer`, `store`, `external-jwt`, `outbound`, `keys`, `subject-revocation`

## Vocabulary
- Trusted issuer: an issuer whose assertions are accepted.
