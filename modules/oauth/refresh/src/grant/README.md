# grant

Internal module of `refresh`: the `refresh_token` grant, and the refresh token `code-grant` adds to a code's answer.

## Responsibilities
- Checks a presented token, rotates its family, and issues the round's access token; starts a family from a code's redemption.

## Not here
- The stores and revocation (`settle`). What `lineage` answers.

## Offers
- `grantOver` and `additionOver` (the build context) → the grant and the addition; `foundingIn` → the founding of families, for `lineage` too.

## Invariants
- Everything that can fail comes before the rotation; the rotation writes only while the family still holds the checked token, and another use, a revocation or a logout coming first revokes the family.
- A rotation whose answer was lost is settled with its first answer; if it cannot be, unavailable, and the family stays. Remainder: a store unreachable past the deadline after the first write turns the owner's resend into reuse.
- The current token is checked before the binding; `sender-binding` says whether two bindings are the same.
- Each access token a family issues is linked to it before it is answered.

## Depends on
- `code-grant` (a redemption), `token-endpoint` (the grant), `client-allowance`, `session` (open sessions), `subject-revocation` (the boundary), `issuer` (its URL), `sender-binding`, `clients`, `kernel`; `settle`, the package's records and store interfaces
