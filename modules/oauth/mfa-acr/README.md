# mfa-acr

## Responsibilities
- Offers the acr a second factor meets as an entry of `acr`'s table, bridging `mfa` and `acr`.

## Not here
- `acr`'s decisions and its table, the operator's included: `acr`.
- Factors, and the amr a second factor gives: `mfa`.

## Offers
- Contribution to `acr`'s table: `urn:o3co:acr:mfa`, met by the amr `mfa` gives a second factor.

## Invariants
- Boot is refused where no second factor is composed.
- The acr's name never changes, as clients already ask for it by that name.

## Data
- None.

## Depends on
- `kernel`, `acr`, `mfa` (composed with it), `mfa-extensions` (`secondFactorAmr`), `mfa-reading` (the contract it asks for, so boot is refused without second factors)
