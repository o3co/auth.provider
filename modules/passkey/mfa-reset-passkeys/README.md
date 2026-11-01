# mfa-reset-passkeys

## Responsibilities
- Has an operator's reset of a subject's second factors remove its passkeys too: contributes the passkeys' step (`passkey-reset`'s `passkeyResetPart`) to `mfa-reset`'s parts, bridging the two.

## Not here
- The reset's steps, its boundaries, its answer and its audit: `mfa-reset`. Removing the passkeys and the witness's mark: `passkey-reset` and `passkeys`.

## Offers
- Contribution to `mfa-reset`'s `resetParts`: the part named `passkeys`, whose `remove` answers what `passkeyResetPart.passkeys` answers, as it is (done with how many list entries went, or stopped; any other failure thrown).

## Invariants
- The name stays `passkeys`: the reset's audit names the part by it (`parts`, `partsStopped`), as operators read it.
- It moves no boundary: the part runs between the reset's two, after the factors and before the lockout's release, as `mfa-reset` runs its parts.
- Comes once `mfa-reset` and `passkey-reset` are both composed, through `combinations`. Without it, nothing is refused: the reset leaves passkeys as they are.

## Depends on
- `kernel`, `mfa-reset` (the parts), `passkey-reset` (the passkeys' step)
