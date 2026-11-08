# revocation

Internal module of `x509-path`: reading a certificate's revocation material, CRLs and OCSP answers, and what it says.

## Responsibilities
- Reads a certificate's CRL distribution points and OCSP locations, verifies a CRL and an OCSP answer, and judges what each says of a certificate.

## Not here
- Fetching, keeping, which source comes first and what an outage leads to: the caller's. The path's rules: `x509-path`.

## Offers
- `distributionPointsOf` (a certificate) → `none` (no extension), `malformed` (one that does not parse), or the points: the http and https full names usable, and how many points give none.
- `verifyCrl` (DER, the issuer, a time, the allowance ahead, the signature algorithms taken) → a `VerifiedCrl` (its issuer, this and next update, its CRLNumber where it has one, what it lists by serial), or why it is unusable. `crlSays` (a `VerifiedCrl`, a certificate, its issuer, a time) → `Judged`: good or revoked (on hold or not) until its next update or the issuer's end, or unusable.
- `ocspUrlsOf`, `ocspRequestOf` (a certificate, its issuer, a nonce), and `judgeOcsp` (DER, a certificate, its issuer, `Asked`) → `Answer`.

## Invariants
- Nothing in revocation material is used before its signature is checked by an algorithm the path would take.
- CRL: read from http and https full-name points covering every reason and naming no other issuer.
- CRL: the issuer's key usage, where given, signs CRLs; no next update is stale, as of each time it is judged.
- CRL: a delta or scoped CRL, an indirect entry, or any other critical extension is unsupported.
- CRL: its CRLNumber is read whole, however large.
- OCSP: the request names the certificate by SHA-1 hashes of its issuer's name and key, with a nonce the answer must carry back where asked.
- OCSP: the signer is the issuer, or a responder it signed: in date, for OCSP signing, held to the path's key and signature rules, with no unknown or unparsable extension.

## Depends on
- `pkijs`, `asn1js`; `x509-path`'s reading of DER, path rules and `signatures`
