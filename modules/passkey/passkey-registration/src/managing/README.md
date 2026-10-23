# managing

Internal module of `passkey-registration`: the session's subject's own passkeys.

## Responsibilities
- Lists, renames and removes the subject's passkeys through `passkeys`' `registrations`.

## Not here
- The records and what removing one ends (`passkeys`). Entering the session and the POST route (`exchange`).

## Offers
- `managingRoutes` (`exchange`, `registrations`, audit) → `list`, `rename` and `remove`, as the package's card says.

## Invariants
- An `id` is a non-empty string, and a `nickname` a label (`labels`' `isLabel`); otherwise `invalid_request`. An id the subject does not hold is `404 not_found`.
- `passkey.renamed` and `passkey.removed` are recorded once done, with the subject and `source`; never the id or the nickname.

## Depends on
- `passkeys`, `labels`, `audit`, `http`; `exchange`; the package's audit events.
