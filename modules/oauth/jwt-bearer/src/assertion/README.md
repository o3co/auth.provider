# assertion

Internal module of `jwt-bearer`: checking a JWT assertion, all but its single use.

## Responsibilities
- Reads an assertion's issuer and signer unverified, checks the signer's shape, and verifies it with that issuer's signers' keys through `external-jwt`.

## Not here
- Which issuers are trusted and their signers (`issuers`, over the package's `signers`). Spending the `jti`, the subject a token is for, and issuing it (the package).

## Offers
- `check` (assertion, signers by issuer, the prefixes of issuers that take self-issued signers) → valid (the trusted issuer it is read as, the `iss` as sent, the subject it stands for, `jti`, expiry, and when it says it was made) / invalid with the reason the grant answers.

## Invariants
- Nothing read unverified reaches a key source unchecked: the issuer must be a string and trusted, the subject well formed as `users` bounds a subject (1 to 255 ASCII characters, as OpenID Connect Core bounds one; a key thumbprint where its issuer says so), and a `kid` text of 1 to 256 well-formed characters.
- With thumbprints, only the key whose thumbprint is the `sub` verifies it; a contributed key is verified with the `sub` it was asked for.
- Every refusal before the signature holds is `untrusted signer`: no JWT read, no trusted issuer, a signer of the wrong shape, no key or none that fits, an algorithm not taken, a malformed header, a signature that does not hold. One after it (`external-jwt`'s `signed`) keeps its words.
- The verified `sub` must be the one read unverified; `jti` is text of 1 to 256 well-formed characters.
- A self-issued signer's `iss` is an issuer's prefix, compared as written (no case folding, decoding or normalization), and 43 characters of base64url, its thumbprint; its `sub` is that same `iss`. Its keys are asked by the thumbprint, and only the key whose own thumbprint it is verifies.
- A key source that cannot answer throws Unavailable.

## Depends on
- `external-jwt`, `kernel`, `users` (the subject's shape); the package's `signers`
