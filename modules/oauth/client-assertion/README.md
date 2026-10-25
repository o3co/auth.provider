# client-assertion

## Responsibilities
- Contributes `private_key_jwt` (RFC 7523) to `clients`: the client signs a JWT with one of its keys, used once.
- Contributes the client metadata section that holds the client's keys, its internal module `keys`.

## Not here
- Client records, lookup, and choosing among methods: `clients`. OAuth error responses: `token-endpoint`.
- Checking the header, key, signature, times, issuer, audience and subject: `external-jwt`, under the policy below.
- Fetching a key set, and how long it is kept: `external-jwt`, through `outbound`.

## Offers
- Composition definition: the method, which names the asymmetric algorithms it takes.
- The client metadata section `client-assertion`: `keys`, public RSA, EC or OKP keys as JWKs, default empty.
  - Each is read by `keys`' rules for outside keys: no private member, a `kid` that is a string, `use` `sig` and `key_ops` holding `verify` where given.
  - Or `jwks-uri`: where the client publishes its key set, an https URL (http only where `outbound` allows plain http), as `url-setting` takes it; never beside written keys. A registered client's `jwks-uri` that `outbound`'s policy refuses refuses boot, with the keys to set (`outbound.refusals`).
  - `accept-loose-audience` (default false): also takes the client's assertions for a loose audience, below. A temporary compatibility setting, to be removed.
  - Any other key is refused at boot.
- Store interface for spent assertions: save a name for a lifetime, answering `created` or `exists`.
  - Requirements: no eviction, survives a crash, never rolled back by failover.
- Operator section: `max-lifetime` (`1s` to `1d` in whole seconds, default `1h`) and `clock-skew` (`0s` to `5m`, default `30s`), each written with its unit; `algorithms` (asymmetric ones `external-jwt` knows; default RS256, ES256, ES384, ES512, EdDSA, one for each kind of key).
- Test configuration builders, the section for test clients, and the contract test of the store interface (`./testing`).

## Invariants
- The three values are read from the body only, a form or a JSON object; never from the query.
- A request carrying `client_assertion` or `client_assertion_type` is this method's alone (RFC 7521 §4.2.1).
- Only one of the two, an empty `client_assertion`, or either part or `client_id` given twice or, in JSON, not as a string is malformed credentials, before anything is judged or spent.
- An assertion type other than `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` is refused, never left to another method.
- `client_id`, when given, names the client; otherwise the assertion's `iss` does.
- `iss` and `sub` are the client's id.
- `aud` is `issuer`'s URL as one string, judged before the `jti` is spent: the token endpoint's URL, or a list, could be for another authorization server that names this one's token endpoint.
- A client whose section sets `accept-loose-audience` is also taken with a loose audience: the token endpoint's absolute URL from `token-endpoint`, or a list holding either URL. Each is logged as a `client-assertion.loose_audience` warning with the client.
- Without the token endpoint's URL from `token-endpoint`, boot is refused, whether or not a client accepts a loose audience.
- The assertion is checked against the client's own keys, written or at its `jwks-uri`, in the operator's `algorithms`; the method names them. Each key is read under one algorithm (`external-jwt`): with two taken for one kind (RS256 and PS256), every client's key of that kind naming no `alg` is unused, so a client's JWK best names its `alg`. A key set is fetched from its URL's host alone; while it cannot be fetched, the answer is unavailable.
- The longest lifetime is `max-lifetime`; the clock allowance is `clock-skew`.
- `jti` is a well-formed string of 1–256 characters.
- The `jti` is spent last, after every other check.
- A spent `jti` is kept per client, past the assertion's end by the allowance and a minute for the store's clock.
- A spent `jti` is refused. One the store cannot answer for is unavailable.
- A refusal tells the caller nothing more; its reason is logged.

## Data
- Spent assertions, named by a hash of the client id and the `jti` together, so no two clients' names meet.

## Depends on
- `kernel`, `http`, `url-setting`, `clients`, `issuer`, `token-endpoint`, `external-jwt`, `keys`, `outbound`, `outbound-policy`

## Vocabulary
- assertion: a JWT the client signed with its own key to prove itself.
- spent assertion: an assertion whose `jti` was used, kept so it cannot be used again.
- loose audience: an assertion's `aud` that is not `issuer`'s URL as one string, but names it or the token endpoint.
