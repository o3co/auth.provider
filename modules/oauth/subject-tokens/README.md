# subject-tokens

## Responsibilities
- Fails an access token that stood before its subject's revocation, and refuses a bundle of credentials for an erased subject.

## Not here
- Recording and comparing the revocation boundary: `subject-revocation`.
- Verifying the token itself: `tokens`.

## Offers
- `tokens`' subject check: a token's subject and standing time → holds or revoked.
- `tokens`' issuance fence: a bundle's subject and receipt id → passed, or refused where `subject-revocation`'s erasure fence answers `erased`.
- `subject-revocation`'s erasure guard: where erasure is enabled, this module is what lets a composition start.

## Invariants
- A token's standing time, as tokens hands it (its standing claim where it carries one, else its issue time), counts as the time its subject authenticated.
- The comparison and the fence are `subject-revocation`'s, never repeated here.
- Its guard holds because the module both checks and fences: `tokens` refuses `subject-check = none` beside a subject check, so a composition with this module checks subjects.
- A comparison that cannot be made is unavailable, never holds or revoked.

## Depends on
- `kernel`, `tokens`, `subject-revocation`
