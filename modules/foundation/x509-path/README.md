# x509-path

## Responsibilities
- Validates an X.509 certification path to the anchors, under rules its caller gives, with its signature rules. Knows no feature.
- Reads the revocation material of a certificate on the path, CRLs and OCSP answers, through `revocation`, and judges what it says.

## Not here
- Which certificate to check, which rules hold, where material comes from, keeping it, and what a result leads to: the caller's.
- Fetching: the caller's.

## Offers
- `certificateOf` (DER) → the certificate, or none for anything that is not one.
- `trustOf` (anchors, intermediates, whether anchors must be self-signed) → `Trust`, read once by a caller.
- `pathOf` (the leaf, what the peer sent, a `Trust`, `PathRules`, a time) → the path, or a `PathRefusal`: the one chain `choice` picks within its bounds, validated by the engine and held to the rules.
  - `PathRules`: the most intermediates (0 to 14; any other is a TypeError), the signature algorithms, the fewest RSA bits, the EC curves taken (any where none are given), the purposes and whether the leaf's or every certificate's extended key usage is held to them, and the key usage bits the leaf's must allow one of.
- `signatureAlgorithms` and `SignatureAlgorithm`, as `signatures` names them.
- CRL, OCSP: `revocation`'s `distributionPointsOf`, `verifyCrl`, `crlSays`, `ocspUrlsOf`, `ocspRequestOf` and `judgeOcsp`, as its card says.
- `./testing`: a test authority for its own and its callers' tests.
  - Keys: `ecKeys`, `rsaKeys`, `pssKeys`. Certificates: `issue`, `hierarchy` (a root, an intermediate and a client leaf), `pemOf`, and `restated` (another algorithm stated beside the signature).
  - Revocation: `crlOf`, `ocspOf`, and `pointAt`, a distribution point. Names for constraints: `dns`, `ip`, `subtree`.

## Invariants
- The path is chosen by the internal module `choice`, bounded and every edge checked, and the engine validates that chain alone, each certificate's issuer the next on it.
- Anything not one certificate is malformed.
- A path is refused for more intermediates than allowed, or an RSA key below the bits.
- A path is refused for a signature not among the rules' algorithms, anchors aside: SHA-2 RSA, PSS over SHA-2 or ECDSA, each named. An anchor's own signature is neither verified nor held to them, as RFC 5280 trusts its key; its extended key usage, key strength, curve and extensions are held as every certificate's.
- It is refused too for a signature stated beside it otherwise than inside, or of another family than its signer's key.
- A path is refused for an EC key on a curve not taken where curves are given (P-256, P-384, P-521, by name), anchor included; the RSA bits hold the anchor too.
- A path is refused for an unknown critical extension, or an extension not parsing as its kind, anchor included.
- A path is refused for a CA leaf, or an issuer past its path length (self-issued CAs not counted).
- A certificate's extended key usage, where it has one, names one of the rules' purposes: the leaf's alone, or every certificate's on the path, anchor included, as the rules say. The leaf's key usage, where given, allows one of the rules' bits.
- Every DNS and IP name on the path (a self-issued CA's aside) lies in a permitted subtree of its kind of each CA above, and in no excluded one (RFC 5280 §4.2.1.10).
- DNS compares by labels in any case (a leading dot: below it alone); IP by network, in its own family.
- Constraints on other kinds of name, or limiting depth, refuse the path.

## Depends on
- `pkijs`, `asn1js`; nothing in the workspace

## Vocabulary
- anchor: a certificate the caller trusts as the end of a path.
- path: the certificates from the leaf to an anchor.
