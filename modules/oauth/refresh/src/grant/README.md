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
- A reuse ends the family first, then reads `subject-revocation`'s `erasedSubjects` and records `refresh.family_revoked`: with the subject where it reads not erased; without it, `withheld` `erased` where erased, `unread` where it cannot be read, logged `refresh.reuse_subject_unread`; a read failing other than unavailable is recorded so too, then thrown. The client's answer is unchanged but for that fault. Cost: while `subject-revocation` cannot be read, a reuse is recorded without its subject.

## Depends on
- `token-endpoint` (the grant), `client-allowance`, `session` (open sessions), `subject-revocation` (the boundary, `erasedSubjects`), `issuer` (its URL), `sender-binding`, `audit`, `kernel`; `founding` (a family's secrets), `settle`, the package's records and store interfaces
