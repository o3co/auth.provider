# voiding

Internal module of `code-grant`: voiding a code that came again, and retrying what failed.

## Responsibilities
- Lists a code void, marks it, revokes its token and ends what the additions gave; on each host, every `sweep-interval`, settles again every code still listed.

## Not here
- Using a code up and deciding it came again (the grant). How a token is revoked (`tokens`).

## Offers
- `voiding` (the code store, the redemption records, the void list, tokens, log, additions) → `settle` (one code's name) and `sweep` (one pass over the list).

## Invariants
- A code is listed first, whatever it holds, then marked void on its redemption record and on its own. A listed code's token is revoked, then the additions' revocations run, then it leaves the list.
- One whose token is not yet noted stays listed: the request issuing it reads the mark and voids again. One that gave nothing leaves once both records end; one with neither record is logged and removed.
- A crash between a code's use-up and its redemption record keeps a reuse listed until the code ends; so does a code refused at the record's creation for its erased subject (`erased`), its entry staying until the code ends.
- A code that comes again after its own record ended is settled where its redemption record is there, which outlives it: its token is revoked from that record.
- Until 0.22, a token on the code's own record, a 0.19 instance's or noted there too, is read and revoked too.
- A record gone is never written back; a mark rewrites what the record holds and keeps its end.
- Settling a code twice, on two hosts at once, does no harm.

## Depends on
- `kernel` (log, `Unavailable`), `tokens` (revoking by reference); the package's records and store interfaces.
