# calls

## Responsibilities
- Makes the ledger's calls through `outbound`, and reads each answer once into a `users` answer, as the package card's tables say.

## Not here
- Which URLs exist and whether outbound's policy takes them (the module). The URL, credential and caps are handed in.
- The calls' shape and how each answer is read: the operator's contract, in `users-http`'s own card.

## Offers
- `calls(parts)`: `verify(url, identifier, password)`, the password call, and `lookup(url, asked)`, which posts `asked` and reads the answer as a lookup.

## Invariants
- A destination refused, a redirect, no answer in time or size, and every answer read as unavailable throw `Unavailable`, logging one `users-http.ledger_failed` warning with the status, or the kind alone: outbound's refusal reason or failure, `credential-refused`, `no-answer` or `malformed`. None is not logged.
- An error or log line carries no text or bytes from the ledger, and no password.
- A user is a new frozen value. Attributes keep the ledger's values as given.

## Depends on
- `kernel`, `outbound`, `users`
