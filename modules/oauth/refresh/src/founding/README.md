# founding

Internal module of `refresh`: how a family begins, from a code's redemption or a `start`, and how a redemption's family is taken back.

## Responsibilities
- Names a new family, picks its binding, and writes its first record and refresh token; starts one from a code's redemption as `code-grant`'s addition, and takes back the family a redemption started when the code comes again.

## Not here
- Rotating a family's token (`grant`). The stores and revocation (`settle`). What `lineage` answers.

## Offers
- `additionOver` (the build context) → `code-grant`'s addition; `foundingIn` (the build context) → the founding of families, for the addition and `lineage`'s `start`; `founding`, `text` and `Random`, the family's names and secrets; `familyFieldsOf` (a redemption or a beginning, its binding) → the family's fields.

## Invariants
- A family starts only for a client allowed the refresh grant; a binding is attached to a public client's family, and to a confidential one's where set, only when it starts.
- A family is saved for its subject; a save the family store answers `erased`, its subject's erasure fencing it, is unavailable, never `exists`: no family starts, and a retry never passes.
- From a redemption, the family's selection is kept (`follow`) first: a selection that cannot be kept fails the start.
- Then the session is read again: one that no longer enters (a close that came meanwhile) fails the start as unavailable, no record written.
- The family's record is written next, then its redemption, under the redemption's name. That create decides every order with a take-back: one first, finding no redemption, writes `taken`, so the create answers `exists`, the family is revoked here and the start fails; one after finds the family and revokes it. A crash between the record and its redemption leaves a family no redemption reaches: its secret never left memory, and it is erasable and ends.

## Depends on
- `code-grant` (a redemption), `session` (whether the redemption's session still enters), `client-allowance`, `clients` (the client's kind), `sender-binding` (the binding), `kernel`; `settle`, the package's records and store interfaces
