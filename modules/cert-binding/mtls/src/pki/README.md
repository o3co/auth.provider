# pki

## Responsibilities
- Validates a client certificate's path to the anchors. Knows no feature.
- Checks the revocation of every certificate on the path but the anchor, through `revocation`.

## Not here
- Where the certificate comes from, what a result binds, and what an outage leads to: `mtls`.
- Fetching: the caller's sources.

## Offers
- `pkiOver` (path policy, and revocation policy with sources, or none): a check of a leaf, the chain sent and a time.
  - It answers valid, invalid with a reason, revoked, or outage with a reason. No engine type crosses it.
- Whether bytes are one certificate.
- The sources a caller implements: GET or POST of a body (material, outage or refused), the time, randomness.
- A test authority for its own and `mtls`'s tests: certificates, CRLs and OCSP answers.

## Invariants
- The path is built from the leaf, the intermediates sent (copies of the leaf dropped) and the anchors; one not starting with the leaf sent is refused.
- Anything not one certificate is malformed.
- A path is refused for more intermediates than allowed, or an RSA key below the bits.
- A path is refused for a signature other than SHA-2 RSA, PSS over SHA-2 or ECDSA, anchors aside.
- A path is refused for an unknown critical extension, or an extension not parsing as its kind, anchor included.
- A path is refused for a CA leaf, or an issuer past its path length (self-issued CAs not counted).
- A leaf's EKU must allow client authentication, and its key usage, where given, signing or key agreement.
- Every DNS and IP name on the path (a self-issued CA's aside) lies in a permitted subtree of its kind of each CA above, and in no excluded one (RFC 5280 §4.2.1.10).
- DNS compares by labels in any case (a leading dot: below it alone); IP by network, in its own family.
- Constraints on other kinds of name, or limiting depth, refuse the path.
- Revocation is checked by the internal module `revocation`, with the path's RSA bits.

## Depends on
- `pkijs`, `asn1js`; nothing in the workspace

## Vocabulary
- anchor: a certificate the operator trusts as the end of a path.
- path: the certificates from the leaf to an anchor.
