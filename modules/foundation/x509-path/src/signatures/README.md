# signatures

Internal module of `x509-path`, shared by its path rules and by `revocation`: which signature algorithms are taken, and checking a signature.

## Responsibilities
- Names the signature algorithms a policy may take, and tells an algorithm identifier's name.
- Checks a signature with a signer's key.

## Not here
- Which certificates and what material are held to the algorithms: `x509-path` and `revocation`.
- Which algorithms are taken: the caller's rules.

## Offers
- `signatureAlgorithms`: `rsa-pkcs1-sha256|384|512`, `rsa-pss-sha256|384|512`, `ecdsa-sha256|384|512`.
- `isTaken` (an algorithm identifier, the names taken): whether it is one of them.
- `fitsKey` (an algorithm identifier, a key): whether the algorithm is of the key's family.
- `sameAlgorithm` (the algorithm signed inside, the one stated beside the signature): whether they are one.
- `isSignedAsTaken` (a certificate, its signer, the names taken): whether it states an algorithm taken, alike inside and out, of its signer's key.
- `signedBy` (a signer, the signed bytes, the signature, its algorithm): whether the signature holds by an algorithm of the signer's family, false rather than failing.

## Invariants
- PSS is named by the hash its parameters give, its mask MGF1 over that hash and its trailer the one defined; SHA-1, its default, any other mask or trailer, and parameters that do not parse name nothing.
- RSA PKCS #1 fits an RSA key, PSS an RSA or PSS key, ECDSA an EC key: the engine checks a signature by its key's family, so a family stated apart from the key's is refused.
- SHA-1 RSA and ECDSA, EdDSA (the engine cannot verify it) and any other identifier name nothing, so none is taken.

## Depends on
- `pkijs`, `asn1js`
