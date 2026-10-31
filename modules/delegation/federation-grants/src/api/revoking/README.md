# revoking

Internal module of `api`: a grant revoked by its client.

## Responsibilities
- Writes a grant revoked, without credentials, and audits it once, when this request's write revoked it.

## Not here
- A revocation the subject's boundary covers: `routing`'s backstop and the follower.

## Offers
- `revokingWith` (the api's common parts) → `revoke`.

## Invariants
- A revocation is answered `204` whatever the grant's state.

## Depends on
- `clients`, `http`; `grant`, the api's common parts.
