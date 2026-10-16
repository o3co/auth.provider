# subject-tokens

## Responsibilities
- Fails an access token that was issued before its subject's revocation.

## Not here
- Recording and comparing the revocation boundary: `subject-revocation`.
- Verifying the token itself: `tokens`.

## Offers
- `tokens`' subject check: a token's subject and issue time → holds or revoked.

## Invariants
- A token's issue time counts as its subject's authentication time.
- The comparison is `subject-revocation`'s, never repeated here.
- A comparison that cannot be made is unavailable, never holds or revoked.

## Depends on
- `kernel`, `tokens`, `subject-revocation`
