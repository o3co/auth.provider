# revocation

## Responsibilities
- Checks the revocation of every certificate on a validated path but the anchor, by CRL, OCSP or both.
- Keeps what sources said, and tells an outage from a refusal.

## Not here
- Building and validating the path, and the key and extension rules it holds a responder to: `pki`.
- Fetching: the caller's sources.

## Offers
- `revocationOver` (revocation policy, the path's RSA bits, sources): a check of a path, answering good, revoked, or a refusal or an outage with a reason.

## Invariants
- Nothing in revocation material is used before its signature is checked by an algorithm the path would take.
- Material is used from its this update (up to the allowance ahead) to its next update, or for a set time without one.
- CRL: read from http and https full-name points covering every reason and naming no other issuer.
- CRL: the issuer's key usage, where given, signs CRLs; no next update is stale.
- CRL: a delta or scoped CRL, an indirect entry, or any other critical extension is unsupported.
- OCSP: the request names the certificate by SHA-1 hashes of its issuer's name and key, with a nonce the answer must carry back where asked.
- OCSP: the signer is the issuer, or a responder it signed: in date, for OCSP signing, held to the path's key rules, with no unknown or unparsable extension.
- OCSP: a delegated responder's own revocation is checked before its good is taken, unless it says it needs none.
- Under both, OCSP comes first, and the CRL may only add a revocation to an unknown.
- Any certificate revoked revokes the path.
- Only a fetch that failed (unreachable, out of time or size, a server failing, busy or timed out, a responder's internal error or try later) is an outage.
- Anything else not confirmed good refuses, and a refusal outweighs an outage.
- One check fetches from at most the policy's number of sources; past them is an outage, not remembered as failing.

## Data
- CRLs by location, until their next update, their issuer's end, or their time to live.
- OCSP answers by the issuer's name and key and the serial, until they end or their signer does.
- A revocation other than a hold (certificateHold), by issuer and serial, after what said it ends; a hold is asked again.
- A failed source, not asked again for a while.
- Each held to a number of entries, oldest first out, in this process alone; checks under way together look each up one at a time.

## Depends on
- `pkijs`, `asn1js`; `pki`'s reading of DER, signatures and the path's key rules
