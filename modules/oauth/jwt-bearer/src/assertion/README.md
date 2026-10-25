# assertion

Internal module of `jwt-bearer`: checking a JWT assertion, all but its single use.

## Responsibilities
- Reads an assertion's issuer and signer unverified, checks the signer's shape, and verifies it with that issuer's signers' keys through `external-jwt`.

## Not here
- Which issuers are trusted and their signers (the package's `signers`). Spending the `jti`, the subject a token is for, and issuing it (the package).

## Offers
- `check` (assertion, signers by issuer) → valid (issuer, subject, `jti`, expiry, and when it says it was made) / invalid with the reason the grant answers.

## Invariants
- Nothing read unverified reaches a key source unchecked: the issuer must be trusted, the subject well formed as `users` bounds a subject (1 to 255 ASCII characters, as OpenID Connect Core bounds one; a key thumbprint where its issuer says so), and a `kid` text of 1 to 256 well-formed characters, or the assertion is malformed.
- With thumbprints, only the key whose thumbprint is the `sub` verifies it; a contributed key is verified with the `sub` it was asked for.
- An unknown signer, a key that does not fit and a signature that does not match get the same answer.
- The verified `sub` must be the one read unverified; `jti` is text of 1 to 256 well-formed characters.
- A key source that cannot answer throws Unavailable.

## Depends on
- `external-jwt`, `kernel`, `users` (the subject's shape); the package's `signers`
