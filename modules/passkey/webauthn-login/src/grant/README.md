# grant

Internal module of `webauthn-login`: the passkey login grant, from the assertion to the tokens.

## Responsibilities
- Turns an assertion of a discoverable passkey into an access token, and a refresh token for a client allowed one, for the passkey's holder.

## Not here
- The options route (`options`). Checking the ceremony and keeping challenges (`passkeys`). The token endpoint's checks before a grant runs (`token-endpoint`).

## Offers
- `passkeyGrantIn` (the build context) → the grant, taking `passkeys`' passkeys, `refresh`'s lineage, `subject-revocation`, `audit` and the issuer from the assembly.
- `passkeyGrant` (those parts, given directly) → the same grant.

## Invariants
- The order, the refusals and the amr are the package's (its card).

## Depends on
- `audit`, `client-allowance`, `grants`, `issuer`, `kernel` (the build context), `refresh`, `subject-revocation`, `passkeys`; the package's contract and audit events
