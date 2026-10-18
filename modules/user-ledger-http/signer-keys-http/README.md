# signer-keys-http

## Responsibilities
- Contributes one issuer's signer keys to `jwt-bearer`: asks the operator's HTTP ledger for a signer's public keys on every assertion, through `outbound`, so a revoked device stops at once.
- Reads each answer once, at this boundary, into `jwt-bearer`'s answer.

## Not here
- Verifying the assertion, the subject's shape, and the algorithms the grant takes (`jwt-bearer`). Whether the ledger may be reached, redirects, and the caps on size and time (`outbound`). Which devices hold which keys (the ledger's).

## Offers
- Composition definition only (a contribution to `jwt-bearer.signer-keys`, keyed by its issuer).
- Operator section: `issuer` (required: the `iss` it answers for, one of `jwt-bearer`'s `issuers` with no keys of its own); `keys-url` (required: the URL whole, https or a plain-http pair outbound names, no fragment); `credential` (optional: `keys`' `bearerToken` of at least 32 bytes of key material, never a `REPLACE-` sample), sent on every call; `timeout` and `max-response-size`, each narrowing outbound's cap, written with its unit.
- The call: `POST {keys-url}` with the URL as written, nothing added; `Content-Type` and `Accept: application/json`; `Authorization: Bearer {credential}` when one is set, none otherwise; the body `{"issuer", "subject", "kid"}`, `kid` only where the assertion names one.

  | Answer | Read as |
  |---|---|
  | `200`, a JSON object with `keys`, a list of JWKs, and `algorithms`, optional, among `EdDSA`, `ES256` and `RS256` | the keys with no private member, and the algorithms, or all three when none are named |
  | `404` (not known) or `410` (known, and revoked) | none |
  | anything else, a `200` whose keys are all private or whose algorithms the grant does not take included | unavailable |

## Invariants
- Nothing is kept between assertions: each asks the ledger again.
- A JWK with a private member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) is never handed on; an answer with no other key is unavailable.
- The ledger is reached only through `outbound`, at the URL's host alone; a redirect is not followed. The URL is an internal destination: a private address is reached only when its host is in `outbound.internal-hosts`.
- Boot is refused on a `keys-url` that outbound's destination policy refuses.
- A destination refused when sending, or no answer in time or size, is unavailable. Each failure logs one `signer-keys-http.ledger_failed` warning with its status, or its kind alone: outbound's refusal reason or failure, `no-answer` or `malformed`. None is not logged. No text or bytes from the ledger, nor the credential, are logged.
- Holds no state, so it is safe on multiple instances.

## Depends on
- `kernel`, `jwt-bearer`, `outbound`, `url-setting`, `keys` (the credential's rule)
