# material

Internal module of `keys`: reading public key material from outside, by one set of rules.

## Responsibilities
- Reads a public key written as PEM or as a JWK, rebuilds a JWK from its public members, tells whether a JWK may verify under an algorithm, answers a key's thumbprint, and tells whether a compact JWS is written in its one form.

## Not here
- The provider's own keys and signing (`signing`). Which outside keys a module trusts (the module's).

## Offers
- `publicJwk`, `publicPem`, `publicMembers`, `verifiesUnder`, `verifyAlgorithms`, `isVerifyAlgorithm`, `thumbprint`, `isCanonicalJws` and `canonical` (whether a base64url text is its bytes' one form).

## Invariants
- A key member is taken only in the one base64url form its bytes encode, so one key has one JWK.
- A private member, a `kid` that is no string, or a private PEM is refused before the platform reads the key.
- The platform reads the key (`createPublicKey`); jose is used only for the thumbprint, and stays inside `keys`.

## Depends on
- None (`keys`' contract)
