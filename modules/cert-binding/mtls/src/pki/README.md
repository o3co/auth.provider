# pki

## Responsibilities
- Validates a client certificate's path to the anchors, through `x509-path`. Knows no feature.
- Checks the revocation of every certificate on the path but the anchor, through `revocation`.

## Not here
- Where the certificate comes from, what a result binds, and what an outage leads to: `mtls`.
- Fetching: the caller's sources.

## Offers
- `pkiOver` (path policy, and revocation policy with sources, or none): a check of a leaf, the chain sent and a time.
  - It answers valid, invalid with a reason, revoked, or outage with a reason. No engine type crosses it.
- Whether bytes are one certificate.
- The names of the signature algorithms a policy may take, `x509-path`'s.
- The sources a caller implements: GET or POST of a body (material, outage or refused), the time, randomness.

## Invariants
- The path is chosen by `x509-path` from the client's chain as sent, within its fixed bounds, every edge checked, toward a trust read once at boot from the operator's anchors as written (none required to be self-signed).
- It is validated by `x509-path` under the policy's rules (its anchors, intermediates, RSA bits and signature algorithms, no EC curve asked), as its card states each, with the leaf's extended key usage alone held to client authentication and its key usage, where given, to signing or key agreement; a refusal for another purpose is told as not for client authentication.
- Revocation is checked by the internal module `revocation`, with the path's RSA bits and signature algorithms.

## Depends on
- `x509-path` (the path, its rules, reading CRLs and OCSP answers); `pkijs`, `asn1js`

## Vocabulary
- anchor: a certificate the operator trusts as the end of a path.
- path: the certificates from the leaf to an anchor.
