# jti-ledger-http

## Responsibilities
- Gives `jwt-bearer` one issuer's ledger of used assertions: asks the operator's HTTP ledger to use each assertion's `jti` up, through `outbound`, so a service sharing that ledger and the grant never both accept one assertion.
- Reads each answer once, at this boundary, by its status alone.

## Not here
- Verifying the assertion and when the ledger is asked (`jwt-bearer`). Whether the ledger may be reached, redirects, and the caps on size and time (`outbound`). Keeping the record (the ledger's).

## Offers
- Composition definition only (a contribution to `jwt-bearer.jti-ledgers`, keyed by its issuer). Opt-in: no axis's default, so composing `jwt-bearer` alone never brings it.
- Operator section:
  - `issuer` (required: the `iss` whose assertions it uses up, one of `jwt-bearer`'s `issuers`); `consume-url` (required: the URL whole, https or a plain-http pair outbound names, no fragment).
  - `credential` (optional: `keys`' `bearerToken` of at least 32 bytes of key material, never a `REPLACE-` sample), sent on every call; `credential-header` (optional: the header the credential goes in as it is, such as `x-internal-token`; unset, `Authorization: Bearer`).
  - `timeout` and `max-response-size`, each narrowing outbound's cap, written with its unit.
- The call: `POST {consume-url}` with the URL as written, nothing added; `Content-Type` and `Accept: application/json`; the credential as above, none without one; the body `{"jti", "exp"}`: the `jti` as sent, and `exp` the time it must stay used until (`jwt-bearer`'s `keepUntil`) in whole seconds, rounded up.

  | Answer | Read as |
  |---|---|
  | `204` | first: used up now |
  | `409` | replayed |
  | any other status, `200` and `201` included, no answer in time or size, a refused destination | unavailable |

## Invariants
- The answer's body is never read: the status alone decides, so nothing the ledger says is told on.
- A `jti` over 256 bytes in UTF-8, the most the ledger records, is not sent: unavailable, logged `reason: "jti-too-long"`.
- The ledger is reached only through `outbound`, at the URL's host alone; a redirect is not followed. The URL is an internal destination (`narrower`: `internal`), named to `outbound` as itself: a private address is reached only when its host is in `outbound.internal-hosts` or, over plain http, when `outbound.plain-internal` names its `host:port`, and only at that URL's origin (scheme, host and port).
- Boot is refused on a `consume-url` that outbound's destination policy refuses (saying which of `outbound`'s keys to set), on a `credential` that `outbound.credentials` will not send there, and on a `credential-header` without a credential or one `outbound` refuses to carry a credential (`credentialHeaderRefusal`), each at its key.
- Each failure logs one `jti-ledger-http.ledger_failed` warning with its status, or its kind alone: outbound's refusal reason or failure, `no-answer` or `jti-too-long`. No `jti`, credential, or byte from the ledger is logged; `replayed` is not logged.
- Holds no state, so it is safe on multiple instances.

## Deployment
- The ledger answers `204` to one of two consumes of a `jti` at once, and `409` to the other.
- It keeps each record, through a crash and a failover, as long as any service using it up may still accept that assertion: past the `exp` it was sent by the time the slowest of them accepts after `exp` (`jwt-bearer`'s `clock-skew`, another's raw `exp` with its own allowance) and the hosts' clock differences. Keeping each an hour past the `exp` it was sent covers `jwt-bearer`'s own allowance (`clock-skew`, at most 5 minutes) with room for the others'.
- It keys its records by `jti` alone, across every service using it up: every signer whose assertions it holds is in one trust domain, and a `jti` is unique across all of them. A party that learns another's `jti` can use it up first, refusing that assertion, never letting one be used twice.
- Every service accepting the issuer's assertions uses them up in this ledger; one that does not can accept an assertion the grant accepted.
- Hosts' clocks differ by far less than the time the ledger keeps a record past the `exp` it was sent.

## Depends on
- `kernel`, `jwt-bearer`, `outbound` (also `credentialHeaderRefusal`), `outbound-policy`, `url-setting`, `keys` (the credential's rule); its takes name `credentialPolicy` (`outbound.credentials`) with or without a `credential`, as `outbound` provides it beside `outbound`, so a module of your own providing `outbound` provides it too
