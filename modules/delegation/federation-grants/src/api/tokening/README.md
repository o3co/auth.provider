# tokening

Internal module of `federation-grants`' `api`: a grant's token, and its status.

## Responsibilities
- Answers a grant's upstream token through `refresh`, noting its use, and each outcome short of a token with its status and audited reason; and a grant's status as the client asks it.

## Not here
- Renewing the token under its lock: `refresh`. Who owns a grant: `routing`.

## Offers
- `tokeningWith` (the api's common parts) → `token`, `status`.

## Invariants
- A use is noted only on an active grant, never moving back; one that cannot be noted is still a use.
- When a grant was last used is told only to a client still allowed its connection.

## Depends on
- `clients`, `http`, `kernel`; `grant`, `refresh` (`Current`), `body.ts`, the api's common parts.
