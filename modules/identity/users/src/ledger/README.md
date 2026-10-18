# ledger

## Responsibilities
- Reads a contributed user ledger's answers into users' own: verification, a user by subject or unanswerable, and a user by upstream identity where the ledger looks users up so.

## Not here
- Links, contacts and which answer users gives: users' own.

## Offers
- `contributedSource(ledger, log)`: the ledger as a source of users, marked as having the last word by upstream identity where it looks users up so.

## Invariants
- A ledger's answer is read once into a frozen copy of `subject` and `attributes`; its failure, an ill-formed subject, attributes that are no object, or another subject's user is unavailable, never none.
- Every user answered holds a well-formed subject, else unavailable; a lookup by an ill-formed subject, an empty IdP name or an empty upstream subject is none, and the ledger is not asked.
- Attributes users does not take are left out, each logged by its name alone.

## Depends on
- None (users' contract)
