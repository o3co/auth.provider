# revocation

Internal module of `x509-path`: reading a certificate's revocation material, CRLs and OCSP answers, and what it says.

## Responsibilities
- Reads a certificate's CRL distribution points and OCSP locations, verifies a CRL and an OCSP answer, and judges what each says of a certificate.

## Not here
- Fetching, keeping, which source comes first and what an outage leads to: the caller's. The path's rules: `x509-path`.

## Offers
- `distributionPointsOf` (a certificate) → `none` (no extension), `malformed` (one that does not parse), or the points: their http and https full names, and how many points give none; which a caller fetches is its own.
- `verifyCrl` (DER, the issuer, a time, the allowance ahead, the signature algorithms taken, a signal) → a `VerifiedCrl` (its issuer, this and next update, its CRLNumber where it has one, what it lists by serial), or why it is unusable. `crlSays` (a `VerifiedCrl`, a certificate, its issuer, a time) → `Judged`: good or revoked (on hold or not) until its next update or the issuer's end, or unusable.
- `ocspUrlsOf`, `ocspRequestOf` (a certificate, its issuer, a nonce), and `judgeOcsp` (DER, a certificate, its issuer, `Asked`) → `Answer`.

## Invariants
- Nothing in revocation material is used before its signature is checked by an algorithm the path would take.
- CRL: read from http and https full-name points covering every reason and naming no other issuer.
- CRL: the issuer's key usage, where given, signs CRLs, and the issuer is in date; no next update is stale, as of each time it is judged.
- CRL: a delta or scoped CRL, an indirect entry, or any other critical extension is unsupported.
- CRL: one whose issuer's name is written past 4 KiB is malformed, though it compares equal to the issuer's (real names are well under 1 KiB): a verified CRL keeps that name.
- CRL: its CRLNumber is read whole, up to the 20 octets of value RFC 5280 allows it and a listed serial (§5.2.3, §4.1.2.2), a 0x00 that only marks it positive aside; one longer, or a CRLNumber that is not a non-negative INTEGER, makes the CRL malformed.
- CRL: one past 1 MiB is malformed, unread. One is read allowing as many ASN.1 nodes as its bytes could hold (asn1js's own 10,000 would refuse some 3,300 entries); OCSP answers and certificates keep asn1js's cap.
- CRL: read one at a time in the process, mtls's and outbound's alike, as each peaks while it is read. Measured, not a bound: a dense one of 1 MiB (some 45,000 serials) near 165 MB and 1 s, one of 20-byte serials near 98 MB. A waiter whose signal ends leaves unread, answered `aborted`, a kind apart from unusable as it says nothing of the CRL. The queue of reads has no cap of its own: its callers bound it (each read is a fetch in a caller's place).
- CRL: verified, it keeps copies alone, none of the CRL's bytes: a map entry a serial it lists: measured near 76 B with 16-byte serials, so some 76 MiB for 2^20 of them.
- CRL: judged of a certificate, its issuer's name, its right to sign CRLs and its dates are asked again, every time.
- OCSP: the request names the certificate by SHA-1 hashes of its issuer's name and key, with a nonce the answer must carry back where asked.
- OCSP: the signer is the issuer, or a responder it signed: in date, for OCSP signing, held to the path's key and signature rules, with no unknown or unparsable extension.

## Depends on
- `pkijs`, `asn1js`; `x509-path`'s reading of DER, path rules and `signatures`
