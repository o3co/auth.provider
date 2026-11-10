# revocation

## Responsibilities
- Checks the revocation of every certificate on a validated path but the anchor, by CRL, OCSP or both.
- Keeps what sources said, and tells an outage from a refusal.

## Not here
- Building and validating the path, and the key and extension rules it holds a responder to: `pki`.
- Fetching: the caller's sources.

## Offers
- `revocationOver` (revocation policy, the path's RSA bits and signature algorithms, sources): a check of a path, answering good, revoked, or a refusal or an outage with a reason.

## Invariants
- CRLs and OCSP answers are read and judged by `x509-path`, as its `revocation` card states: nothing in them is used before their signature is checked by an algorithm the path would take.
- Material is used from its this update (up to the allowance ahead) to its next update, or for a set time without one.
- OCSP: a delegated responder's own revocation is checked before its good is taken, unless it says it needs none.
- Under both, OCSP comes first, and the CRL may only add a revocation to an unknown; where OCSP gives no answer it can use, the CRL alone decides.
- Any certificate revoked revokes the path.
- Only a fetch that failed (unreachable, out of time or size, a server failing, busy or timed out, a responder's internal error or try later) is an outage.
- Anything else not confirmed good refuses, and a refusal outweighs an outage.
- One check fetches from at most the policy's number of sources; past them is an outage, not remembered as failing.

## Data
- CRLs as verified once when fetched, by location and the issuer whose key verified them, until their next update, their issuer's end, or their time to live; each check judges what was kept. The serials they list are held to 2^20 together (x509-path keeps some 47 B a serial, so some 50 MB), the oldest CRLs going first; one listing more alone is not kept. A process composing `outbound` holds as much again in its own.
- OCSP answers by the issuer's name and key and the serial, until they end or their signer does.
- A revocation other than a hold (certificateHold), by issuer and serial, after what said it ends; a hold is asked again.
- A failed source, not asked again for a while.
- Each held to a number of entries, oldest first out, in this process alone; checks under way together look each up one at a time.

## Depends on
- `x509-path` (reading and judging CRLs and OCSP answers); `pkijs`, `asn1js`
