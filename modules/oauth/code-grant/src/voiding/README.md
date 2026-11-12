# voiding

Internal module of `code-grant`: voiding a code that came again, and retrying what failed.

## Responsibilities
- Lists a code void, marks it, revokes its token and ends what the additions gave; on each host, every `sweep-interval`, settles again every code still listed.

## Not here
- Using a code up and deciding it came again (the grant). How a token is revoked (`tokens`).

## Offers
- `voiding` (the code store, the void list, tokens, log, clock, additions) → `settle` (one code's name) and `sweep` (one pass over the list).

## Invariants
- A code is listed first, whatever it holds, then marked void. A listed code's token is revoked, then the additions' revocations run, then it leaves the list.
- One whose token is not yet noted stays listed: the request issuing it reads the mark and voids again. One that gave nothing leaves once its record ends; one with no record is logged and removed.
- A record marked void that issued a token lives until that token's end and 120 s more, as the grant keeps it.
- A record gone is never written back; a mark rewrites what the record holds.
- Settling a code twice, on two hosts at once, does no harm.

## Depends on
- `kernel` (log, `Unavailable`), `tokens` (revoking by reference); the package's records and store interfaces.
