# grant

Internal module of `refresh`: the `refresh_token` grant.

## Responsibilities
- Checks a presented token, rotates its family, and issues the round's access token.

## Not here
- How a family begins, from a code or a `start` (`founding`). The stores and revocation (`settle`). What `lineage` answers.

## Offers
- `grantOver` (the build context) → the grant.

## Invariants
- Everything that can fail comes before the rotation; the rotation writes only while the family still holds the checked token, and another use, a revocation or a logout coming first revokes the family.
- A rotation whose answer was lost is settled with its first answer; if it cannot be, unavailable, and the family stays. Remainder: a store unreachable past the deadline after the first write turns the owner's resend into reuse.
- The current token is checked before the binding; `sender-binding` says whether two bindings are the same.
- Each access token a family issues is linked to it before it is answered.

## Depends on
- `token-endpoint` (the grant), `client-allowance`, `session` (open sessions), `subject-revocation` (the boundary), `issuer` (its URL), `sender-binding`, `audit`, `kernel`; `founding` (a family's secrets), `settle`, the package's records and store interfaces
