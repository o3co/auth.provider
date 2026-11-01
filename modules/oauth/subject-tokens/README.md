# subject-tokens

## Responsibilities
- Fails an access token that stood before its subject's revocation.

## Not here
- Recording and comparing the revocation boundary: `subject-revocation`.
- Verifying the token itself: `tokens`.

## Offers
- `tokens`' subject check: a token's subject and standing time → holds or revoked.

## Invariants
- A token's standing time, as tokens hands it (its standing claim where it carries one, else its issue time), counts as the time its subject authenticated.
- The comparison is `subject-revocation`'s, never repeated here.
- A comparison that cannot be made is unavailable, never holds or revoked.

## Depends on
- `kernel`, `tokens`, `subject-revocation`
