# users-http

## Responsibilities
- Contributes a user ledger to `users`: asks the operator's HTTP ledger to verify an identifier and password, through `outbound`.
- Reads each answer once, at this boundary, into a `users` user.
- Answers every lookup by subject unanswerable: the ledger offers none.

## Not here
- Written links and verified contacts (`users`). Whether the ledger may be reached, redirects, and the caps on size and time (`outbound`). The names of attributes and the shape of a subject (`users`). Hashing passwords (the ledger's).

## Offers
- Composition definition only (a contribution to `users`' `ledgers`).
- Operator section: `verify-url` (the password call's whole URL, https or a plain-http pair outbound names, no fragment; required), `credential` (optional: a bare RFC 6750 token with at least 32 bytes of key material, counted as the fewest of its bytes, hex or base64 decoding), `timeout` and `max-response-size` (each narrows outbound's cap; written with its unit, a bare number refused). `timeout-ms` and `max-response-bytes` are read in their place when given.
- The password call, as the HTTP user repository's `authenticateUrl`:

  | | |
  |---|---|
  | Request | `POST {verify-url}`, `Content-Type` and `Accept: application/json`, the body `{"email": identifier, "password"}` |
  | Credential | `Authorization: Bearer {credential}` when set; none sent otherwise |
  | `200`, a JSON object with an `id` of a subject's shape (`users`) and a non-empty string `username` | the user: `id` is the subject; `email`, `name`, `picture`, `groups` and a boolean `emailVerified` (only beside `email`) are the attributes `users` names for them; other fields are dropped |
  | `200` otherwise | unavailable |
  | `401` or `403` with a Bearer challenge, when a credential was sent | unavailable (the credential is refused) |
  | `401` or `403` otherwise | none |
  | any other status, `404` and other `2xx` included | unavailable |

## Invariants
- The ledger is reached only through `outbound`, at the URL's host alone; a redirect is not followed. The URL is an internal destination: a private address is reached only when its host is in `outbound.internal-hosts`.
- The password goes in the request body alone, never in a URL, a log line or an error.
- Boot is refused on a `verify-url` that outbound's destination policy refuses.
- A destination refused when sending, or no answer in time or size, is unavailable. A wrong URL makes verification unavailable, never "no such user", unless what answers there is a `401` or `403` without a Bearer challenge, which reads as none.
- A user is a new frozen value. Attributes keep the ledger's values as given.
- An error or log line carries no text or bytes from the ledger. Each failure logs one warning with its status, or its kind alone: outbound's refusal reason or failure, `credential-refused`, `no-answer` or `malformed`.
- Boot reports never show the credential.
- The operator's ledger must do the same work for an unknown identifier as for a known one; this module sends the same one request either way.
- Holds no state, so it is safe on multiple instances.

## Depends on
- `kernel`, `users`, `outbound`, `url-setting`
