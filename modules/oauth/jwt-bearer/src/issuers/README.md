# issuers

Internal module of `jwt-bearer`: the trusted issuers, each entry of the section's `issuers`, and the signers and ledgers each is read with.

## Responsibilities
- Reads each entry: its keys written, its key set's URL, or neither (its keys then contributed at `signerKeys`), and how its signers name a subject.
- Builds each issuer's signers, and refuses boot on an entry, or a contribution, that cannot be read as one.
- Reads the delegated issuers (`delegated-issuers`), each with the one module that checks its assertions.

## Not here
- Checking an assertion (`assertion`). The grant's policy (audience, lifetime, clock skew), resolving linked subjects, and spending the `jti` (the package).

## Offers
- `issuersSetting`, the section's `issuers`: a list of `issuer` with `keys` (`kid`, `alg`, `public-key` (SPKI PEM; a private key refuses boot)), `jwks-uri` (where its key set is, at https on the issuer's host), or neither, its keys then contributed. Each issuer's `subject` (`as-is` or `linked`, required), `upstream` (the IdP name its signers are known by, with `linked` only) and `subject-is-key-thumbprint` (default false).
- An entry's `self-issued-prefix` (1 to 64 printable ASCII characters; with thumbprints and keys contributed only): it takes self-issued signers too, whose `iss` and `sub` are the prefix and their key's thumbprint.
- An entry's policy beside the section's: `max-assertion-lifetime` and `clock-skew`, each no wider than the section's; `ceiling`, its `scopes` and `audiences`, each a list not empty; `algorithms` (any there is to take, by default EdDSA, ES256 and RS256), for a key set or keys contributed; `accept-key-set-elsewhere` (default false), for a key set off the issuer's host, at https still.
- An entry's `conditions` on its assertions' verified claims (the `conditions` module's), or `accept-any-subject` (default false), for an issuer whose every signer becomes a subject. The grant asks the conditions once an assertion is verified, before its subject is looked up or its `jti` spent; one not meeting them is `assertion does not meet its issuer's conditions`, telling no value.
- An entry's `profile`: `rfc7523` (default), or `id-jag`, its assertions taken as ID-JAGs by the internal module `id-jag`'s rules (preview).
- An entry's `client`, for a grant naming no client: the registered client its assertions identify where a request names none (RFC 7523 §3.1).
- `linkedOf` (the entries) → each linked issuer's IdP name. `selfIssuedOf` (the entries) → each issuer taking self-issued signers: its prefix and its place.
- `issuersIn` (the build context, the section, the policy for each, this grant's type) → each issuer's signers and ledger, or the refusals; `trustedWith`, the same from what it takes as arguments; `issuersTakes`, what `issuersIn` takes.
- `delegatedSetting`, the section's `delegated-issuers`: a list of issuers, each as sent. `delegatedIn` (the build context, the entries, that list) → each delegated issuer's delegate (`delegatedAssertions`), or the refusals; `delegatedWith`, the same from its arguments; `delegatedTakes`.

## Invariants
- A key set is fetched only at https from its issuer's host, or from its own where the entry accepts a key set elsewhere, which boot warns of at the entry's place (`jwt-bearer.key_set_elsewhere`), never by its URL; a `jwks-uri` not at https or on another host, or with an issuer that is no URL, refuses the boot. While no key set can be had, the issuer's signers are unavailable, and so is the grant for its assertions.
- Boot is refused on an issuer with keys both written and contributed, or neither; on `upstream` without `linked`, or `linked` without it; on `subject-is-key-thumbprint` with a key set, which cannot tell which key signed; and on an issuer without `subject`.
- Boot is refused on an issuer named twice, and on keys or a jti ledger contributed for an issuer the entries do not name.
- Boot is refused on an entry's `max-assertion-lifetime` longer, or `clock-skew` wider, than the section's, at that key.
- An issuer whose every signer becomes a subject is one read as-is, with no thumbprint, its keys the issuer's whole: written, a key set, or contributed without declaring `perSigner`. Boot is refused on such an issuer with neither conditions nor `accept-any-subject`; `accept-any-subject` is refused on any other, and beside conditions; boot warns of it each time at the entry's place (`jwt-bearer.any_subject`), never by its issuer.
- An entry's `client` is a registered client, public with method `none` (nothing it authenticates with), allowed this grant alone, and no other entry's; boot is refused at the entry's `client` on any other, never by its value, so a request naming no client skips no client's authentication and opens no other grant.
- `profile = id-jag` is refused at the entry's `profile` beside `subject-is-key-thumbprint`, a `self-issued-prefix` or a `client`, as `id-jag`'s card says why; held to `conditions` or `accept-any-subject` as any entry.
- `accept-any-subject` is refused beside an entry's `client`: a request naming no client has no authentication, so conditions, a table or keys alone narrow whose assertions it takes. Boot warns of each entry with a `client` each time at its place (`jwt-bearer.clientless_issuer`), never by its issuer or client.
- Boot is refused on a `self-issued-prefix` beside keys written or a key set, or on an issuer without `subject-is-key-thumbprint`; on one that starts any issuer, its own included; and on two that overlap, one starting the other, at both whatever the order, so no assertion can be read as two issuers'. Each refusal of an entry is at its place (`jwt-bearer.issuers.<i>`), never by its value.
- Every start warns `jwt-bearer.self_issued_signers` with the places of the issuers taking self-issued signers, never a prefix.
- Boot is refused on a delegated issuer named twice, that no module checks or two do (naming them), that is an entry's issuer, or that a self-issued prefix starts, so no assertion is read by two rules; each at its place (`jwt-bearer.delegated-issuers.<i>`). And on assertions delegated for an issuer the list does not name.

## Depends on
- `external-jwt` (key sources), `clients` (the registered clients), `client-allowance` (a client's grants), `keys` (reading a PEM), `host-entries` (the key set's host), the package's contract and `signers`, `kernel` (the build context)

## Vocabulary
- Trusted issuer: an issuer whose assertions are accepted.
