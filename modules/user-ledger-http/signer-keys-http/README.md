# signer-keys-http

## Responsibilities
- Contributes one issuer's signer keys to `jwt-bearer`: asks the operator's HTTP ledger for a signer's public keys on every assertion, through `outbound`, so a revoked device stops at once.
- Reads each answer once, at this boundary, into `jwt-bearer`'s answer.

## Not here
- Verifying the assertion, the subject's shape, and the algorithms the grant takes (`jwt-bearer`). Whether the ledger may be reached, redirects, and the caps on size and time (`outbound`). Which devices hold which keys (the ledger's).

## Offers
- Composition definition only (a contribution to `jwt-bearer.signer-keys`, keyed by its issuer). Opt-in: no axis's default, so composing `jwt-bearer` alone never brings it.
- Operator section: `issuer` (required: the `iss` it answers for, one of `jwt-bearer`'s `issuers` with no keys of its own); `keys-url` (required: the URL whole, https or a plain-http pair outbound names, no fragment); `credential` (optional: `keys`' `bearerToken` of at least 32 bytes of key material, never a `REPLACE-` sample), sent on every call; `timeout` and `max-response-size`, each narrowing outbound's cap, written with its unit.
- The call: `POST {keys-url}` with the URL as written, nothing added; `Content-Type` and `Accept: application/json`; `Authorization: Bearer {credential}` when one is set, none otherwise; the body `{"issuer", "subject", "kid"}`, `kid` only where the assertion names one.

  | Answer | Read as |
  |---|---|
  | `200`, a JSON object with `keys`, a list of JWKs, and `algorithms`, optional, among `EdDSA`, `ES256` and `RS256` | the keys `keys` reads as public alone, and the algorithms, or all three when none are named |
  | `404` (not known) or `410` (known, and revoked), or a `200` whose `keys` is empty (no key now) | none |
  | anything else, a `200` with no key `keys` reads as public alone or whose algorithms the grant does not take included | unavailable |

## Invariants
- Nothing is kept between assertions: each asks the ledger again.
- A JWK is handed on only where `keys`' `publicMembers` reads it as public alone: its type's public members, each a string in its one form, and members that describe it (`kid`, `alg`, `use`, `key_ops`); an answer with no such key is unavailable, and one with some left out logs `signer-keys-http.keys_dropped` with their `count` alone.
- The ledger is reached only through `outbound`, at the URL's host alone; a redirect is not followed. The URL is an internal destination, named to `outbound` as itself: a private address is reached only when its host is in `outbound.internal-hosts`, and only at that URL's origin (scheme, host and port).
- Boot is refused on a `keys-url` that outbound's destination policy refuses (saying which of `outbound`'s keys to set, by `outbound.refusals`), and on a `credential` that `outbound.credentials` will not send there (at `credential`); `outbound` sends the credential as its `credential`.
- A destination refused when sending, or no answer in time or size, is unavailable. Each failure logs one `signer-keys-http.ledger_failed` warning with its status, or its kind alone: outbound's refusal reason or failure, `no-answer` or `malformed`. None is not logged. No text or bytes from the ledger, nor the credential, are logged.
- Holds no state, so it is safe on multiple instances.

## Depends on
- `kernel`, `jwt-bearer`, `outbound`, `outbound-policy`, `url-setting`, `keys` (the credential's rule)
