# choice

Internal module of `x509-path`: choosing the one chain a path is validated along, within bounds, from what a peer sent and what the caller trusts.

## Responsibilities
- Reads the caller's trust once, indexed, and chooses the shallowest chain from a leaf to an anchor, every edge checked, its work bounded whatever a peer sends.

## Not here
- Validating the chain chosen, its dates and the rules: `x509-path`'s `pathOf`, through the engine and its rules.

## Offers
- `trustOf` (anchors, intermediates, whether anchors must be self-signed) → `Trust`; a certificate that is not one, or, asked so, an anchor not self-signed, is a TypeError.
- `chosen` (a leaf, what the peer sent, the trust, the most intermediates) → the chain (leaf, intermediates, one anchor), or `malformed`, `path`, or `too many intermediates` where that alone left an issuer out. The most intermediates is 0 to 14; any other is a TypeError.

## Invariants
- An issuer is a certificate node reads as the certificate's issuer (`checkIssued`: names as OpenSSL compares them, key identifiers too) whose key verifies its signature; nothing else is an edge, a self-issued certificate included.
- Breadth first from the leaf; a certificate (by DER) is entered once, so a cycle ends.
- Bounds, the same for every caller but by its `maxIntermediates`, as each hands it a chain an outside party chose: at most 10 certificates sent, or `maxIntermediates` and one more where that is more (every intermediate a caller allows can be sent), 4 issuers to a certificate and 32 certificates entered, and `maxIntermediates` deep; past any, no chain (`path`).
- Issuers come from what was sent, all of it, and from the trust, found by the certificate's authority key identifier and by its issuer name's DER as written. One the trust holds under another encoding of the name, with no key identifiers, is not found: no chain.
- Among the shallowest chains: those sent first, in the order sent, then the trust's, in DER order.
- Cost (20 runs each, against the platform's store of 118 roots and one root more): an ordinary chain of two intermediates 0.9 ms; the most a peer may send, ten certificates and four issuers at a step, 3.3 ms; a cycle of two 0.8 ms.

## Depends on
- node's `X509Certificate`; `pkijs`, `asn1js`; `x509-path`'s reading of DER
