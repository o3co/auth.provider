# tokening

Internal module of `api`: a grant's token, and its status.

## Responsibilities
- Answers a grant's upstream token through `refresh`, noting its use, and each outcome short of a token with its status and audited reason; and a grant's status as the client asks it.

## Not here
- Renewing the token under its lock: `refresh`. Who owns a grant: `routing`.

## Offers
- `tokeningWith` (the api's common parts) → `token`, `status`.

## Invariants
- A token is handed only past the erasure fence, after the grant's own refusals and its refresh: one fenced write per hand-out where erasure is enabled, under a receipt of 128 fresh random bits; with it off, the fence passes writing nothing. `erased` is answered `410 grant_revoked` (`backstop`), as a grant its subject's revocation ended, recording nothing about the subject; a fence that cannot answer is `503`.
- Where erasure is enabled, a token is handed only where its fence's receipt committed before the subject's erasure mark. A request past the fence may still answer after the mark, even after the erasure is done (promise 4). An upstream token handed out lives at the upstream until its end.
- A client's revocation answers `204` while a grant whose subject is erased is held until its eraser runs: right only because this fence refuses its hand-out.
- A use is noted only on an active grant, never moving back; one that cannot be noted is still a use.
- When a grant was last used is told only to a client still allowed its connection.

## Depends on
- `clients`, `http`, `kernel`; `grant`, `refresh` (`Current`), `body.ts`, the api's common parts.
