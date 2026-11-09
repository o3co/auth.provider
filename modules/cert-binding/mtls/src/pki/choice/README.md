# choice

## Responsibilities
- Chooses the shallowest chain from a leaf to an anchor, every edge checked, its work bounded whatever a client sends.

## Not here
- Validating the chain chosen, its dates and the policy: `pki`'s path, through the engine and its rules.

## Offers
- `chosen` (a leaf, what the client sent, the anchors, the most intermediates) → the chain (leaf, intermediates, one anchor), or `malformed`, `path`, or `too many intermediates` where that alone left an issuer out.

## Invariants
- An issuer is a certificate node reads as the certificate's issuer (`checkIssued`: names as OpenSSL compares them, key identifiers too) whose key verifies its signature; nothing else is an edge, a self-issued certificate included.
- Breadth first from the leaf; a certificate (by DER) is entered once, so a cycle ends.
- Bounds: at most 10 certificates sent, or `maxIntermediates` and one more where that is more, 4 issuers to a certificate, and `maxIntermediates` deep; past any, no chain (`path`).
- Among the shallowest chains: those sent first, in the order sent, then the anchors, in DER order.

## Depends on
- node's `X509Certificate`; `pkijs`; `pki`'s reading of DER
