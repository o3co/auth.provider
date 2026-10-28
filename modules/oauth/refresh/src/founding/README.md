# founding

Internal module of `refresh`: how a family begins, from a code's redemption or a `start`, and how a redemption's family is taken back.

## Responsibilities
- Names a new family, picks its binding, and writes its first record and refresh token; starts one from a code's redemption as `code-grant`'s addition, and takes back the family a redemption started when the code comes again.

## Not here
- Rotating a family's token (`grant`). The stores and revocation (`settle`). What `lineage` answers.

## Offers
- `additionOver` (the build context) → `code-grant`'s addition; `foundingIn` (the build context) → the founding of families, for the addition and `lineage`'s `start`; `founding`, `text` and `Random`, the family's names and secrets.

## Invariants
- A family starts only for a client allowed the refresh grant; a binding is attached to a public client's family, and to a confidential one's where set, only when it starts.
- A redemption is written before its family's record, under the redemption's name: a code that comes again finds its family and revokes it, or has already marked that none may start.
- From a redemption, the family's selection is kept (`follow`) before its session lists it: a selection that cannot be kept fails the start with nothing listed, never pushing another family out.
- Once its session lists it, the session is read again: one that no longer enters (a close that came before the list held the family) has the family revoked here, and the start fails as unavailable.
- A family dropped from its session's list ends at once, and its start fails as unavailable.

## Depends on
- `code-grant` (a redemption), `session` (whether the redemption's session still enters), `client-allowance`, `clients` (the client's kind), `sender-binding` (the binding), `kernel`; `settle`, the package's records and store interfaces
