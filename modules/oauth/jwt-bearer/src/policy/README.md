# policy

Internal module of `jwt-bearer`: what a trusted issuer's own policy makes of the section's, for verifying its assertions, keeping them used and issuing their tokens.

## Responsibilities
- Gives an issuer's verifying policy: its algorithms, lifetime and clock skew, and this server's audiences.
- Gives how long a spent assertion stays used, and the ceilings an issuer holds its tokens to.

## Not here
- Reading the entries and refusing them (`issuers`). Verifying (`external-jwt`, through `assertion`). Deciding an issuance within the ceilings (`client-allowance`). When each is asked (the package).

## Offers
- `verifierPolicy` (entry, the section's limits, audiences) → the policy `external-jwt` verifies under; `skewOf` (entry, limits) → its clock allowance in ms.
- `keepUntilOf` (an assertion's `exp`, ms) → until when it stays used; `ceilingsOf` (entry) → its ceilings.

## Invariants
- The audiences an assertion may name are `issuer`'s URL and the token endpoint's absolute URL, as `token-endpoint` tells it; without one, the boot is refused (the package). An ID-JAG's is `issuer`'s URL alone, and its header's `typ` the ID-JAG's (`id-jag`'s `idJagTyp`).
- An entry's lifetime and clock skew are its own where it writes them, else the section's; `issuers` refuses one wider than the section's. Its skew narrows what is taken alone: the `sessions` boundary keeps the section's (the package).
- Algorithms are a written key's own, else the entry's `algorithms`, else EdDSA, ES256 and RS256.
- A spent assertion stays used until five minutes, the widest clock skew any setting takes, and a minute past its `exp`: no setting moves it, so no change of one lets an assertion back.
- An entry's `ceiling` is its tokens' one ceiling; an entry with none holds them to the client's allowance alone.

## Depends on
- `external-jwt` (its policy's form), `client-allowance` (a ceiling's form), the package's contract, `issuers` (an entry's form) and `id-jag` (its type)
