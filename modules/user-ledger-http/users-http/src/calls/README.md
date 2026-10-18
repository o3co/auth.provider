# calls

## Responsibilities
- Makes the ledger's calls through `outbound`, and reads each answer once into a `users` answer.

## Not here
- Which URLs exist and whether outbound's policy takes them (the module). The URL, credential and caps are handed in.

## Offers
- `calls(parts)`: `verify(url, identifier, password)`, the password call, and `lookup(url, asked)`, which posts `asked` and reads the answer as a lookup.
- Every call: `POST {url}` with the URL as written, nothing added; `Content-Type` and `Accept: application/json`; `Authorization: Bearer {credential}` when one is set, none otherwise.
- The password call, as the HTTP user repository's `authenticateUrl`, with the body `{"email": identifier, "password"}`:

  | Answer | Read as |
  |---|---|
  | `200`, a JSON object with an `id` of a subject's shape (`users`) and a non-empty string `username` | the user |
  | `401` or `403` with a Bearer challenge, when a credential was sent | unavailable (the credential is refused) |
  | `401` or `403` otherwise | none; kept for 0.17's ledgers, and to be read as a lookup's are once its owner says |
  | anything else, a `200` of another shape, `404` and other `2xx` included | unavailable |

- A lookup, with the body it is given (`{"subject"}` by subject, `{"idp", "subject"}` by upstream identity):

  | Answer | Read as |
  |---|---|
  | `200`, a JSON object with an `id` of a subject's shape | the user; no `username` is asked for |
  | `404` (not known) or `410` (known, and refused) | none |
  | anything else, `401` and `403` included, challenged or not | unavailable |

- A user: `id` is the subject; `email`, `name`, `picture`, `groups` and a boolean `emailVerified` (only beside `email`) are the attributes `users` names for them; other fields are dropped.

## Invariants
- A destination refused, a redirect, no answer in time or size, and every answer read as unavailable throw `Unavailable`, logging one `users-http.ledger_failed` warning with the status, or the kind alone: outbound's refusal reason or failure, `credential-refused`, `no-answer` or `malformed`. None is not logged.
- An error or log line carries no text or bytes from the ledger, and no password.
- A user is a new frozen value. Attributes keep the ledger's values as given.

## Depends on
- `kernel`, `outbound`, `users`
