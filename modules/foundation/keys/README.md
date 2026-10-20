# keys

## Responsibilities
- Reads the provider's signing key ring at boot, signs and verifies with it, and publishes its public key set (JWKS).
- Reads public key material from outside (PEM and JWK) by one set of rules, for every module that verifies another party's signature.

## Not here
- The meaning of what is signed. Which outside keys a module trusts, and where it gets them.

## Offers
- `keys`: sign claims under a `typ` (adding the `kid`), and verify a token, answering valid with frozen claims or why not (`malformed`, `typ`, `kid_unknown`, `kid_expired`, `signature`).
- Whether signing is asymmetric, the `alg` it signs with, and the path of the public key set, a route contributed to `http` that answers its listed origins.
- `publicJwk`: a JWK the platform reads as a public key, kept as given.
- `publicPem`: a public key written as PEM.
- `thumbprint`: a key's JWK thumbprint (RFC 7638, SHA-256): of a key read, the same whatever form it was written in; of a JWK given, from its required members as written.
- `verifiesUnder`: whether a JWK may verify, under an algorithm or any of `verifyAlgorithms`, typed as `VerifyAlgorithm`; `isVerifyAlgorithm` tells one from any other name.
- `publicMembers`: a JWK rebuilt from its type's public members alone, without reading it.
- `isCanonicalJws`: whether a compact JWS is written in its one form; `verify` answers any other as `malformed`. `secretBytes` (exactly or at least n): the setting of a secret's bytes every module takes, strict base64 of at least 8 byte values, never a `REPLACE-` sample; a refusal never names the value.
- `bearerToken` (at least n): the setting of a bearer token sent to an outside party, an RFC 6750 b64token of at least n bytes and 8 byte values of key material however read (as written, hex or base64), never a `REPLACE-` sample; a refusal never names the value.
- Operator section: `signing` (`kid`, `alg`, and a PKCS8 PEM `private-key`, or for HS256 a hex or base64 `secret`), `next` (`kid`, `alg`, `public-key`), `previous` (`kid`, `alg`, `public-key`, `expires-at`).
- Test configuration builders (`./testing`), with a new Ed25519 signing key unless a test sets one.

## Invariants
- Key material has no default; a missing or unreadable key, or one not of its `alg`'s kind, refuses boot.
- A signing `private-key` not written as PEM is refused by the section, before it is read; so is the fragment's `REPLACE-` placeholder.
- EdDSA takes Ed25519, ES256 takes P-256, RS256 takes RSA of 2048 bits or more; an HMAC secret is 32 bytes or more.
- A previous or next key is the provider's own: a private PEM is taken too, and only its public half is used. The next key is published and verifies, but never signs, so verifiers hold it before it signs.
- A `kid` is 1–128 of letters, digits and `. _ ~ -`, unique in the ring.
- A token is verified by the key its `kid` names, after its `typ`, and refused once that key's `expires-at` is reached.
- A payload the key signed that is no JSON is answered as a bad signature.
- The published set holds public members alone, of unexpired keys; with nothing to publish, it answers 404 `no-store`.
- The set carries a strong ETag, answers 304 to it, and is cached five minutes.
- An outside JWK with a private member, a `kid` that is no string, or a key member not in its one form, is refused; so is a private PEM.
- An outside key may verify only for signatures (`use`, `key_ops`) and only under an algorithm its kind and curve fit.
- Internal modules `material` (outside key material), `secret` (secret settings), `signing` (the provider's key ring) and `jwks` (the public key set).

## Depends on
- `kernel`, `http`

## Vocabulary
- key ring: the current signing key, the next key, and past verification keys still within their expiry.
- claim / `typ`: the content and type of a JWT being signed, owned by the side that asks for the signature.
