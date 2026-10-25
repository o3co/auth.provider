# issuers

Internal module of `jwt-bearer`: the trusted issuers, each entry of the section's `issuers`, and the signers and ledgers each is read with.

## Responsibilities
- Reads each entry: its keys written, its key set's URL, or neither (its keys then contributed at `signerKeys`), and how its signers name a subject.
- Builds each issuer's signers, and refuses boot on an entry, or a contribution, that cannot be read as one.

## Not here
- Checking an assertion (`assertion`). The grant's policy (audience, lifetime, clock skew), resolving linked subjects, and spending the `jti` (the package).

## Offers
- `issuersSetting`, the section's `issuers`: a list of `issuer` with `keys` (`kid`, `alg`, `public-key` (SPKI PEM; a private key refuses boot)), `jwks-uri` (where its key set is, at https on the issuer's host), or neither, its keys then contributed. Each issuer's `subject` (`as-is` or `linked`, required), `upstream` (the IdP name its signers are known by, with `linked` only) and `subject-is-key-thumbprint` (default false).
- `linkedOf` (the entries) → each linked issuer's IdP name.
- `issuersIn` (the build context, the entries, the policy for each) → each issuer's signers and ledger, or the refusals; `trustedWith`, the same from what it takes as arguments; `issuersTakes`, what `issuersIn` takes.

## Invariants
- A key set is fetched only at https from its issuer's host; a `jwks-uri` not at https or on another host, or with an issuer that is no URL, refuses the boot.
- Boot is refused on an issuer with keys both written and contributed, or neither; on `upstream` without `linked`, or `linked` without it; on `subject-is-key-thumbprint` with a key set, which cannot tell which key signed; and on an issuer without `subject`.
- Boot is refused on an issuer named twice, and on keys or a jti ledger contributed for an issuer the entries do not name. Each refusal of an entry is at its place (`jwt-bearer.issuers.<i>`), never by its value.

## Depends on
- `external-jwt` (key sources), `keys` (reading a PEM), `outbound-policy` (the key set's host), the package's contract and `signers`, `kernel` (the build context)
