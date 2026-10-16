# held

Internal module of `conformance-federation`: the scene of a federation login that a gate holds.

## Responsibilities
- Checks that a login through an upstream that the user's second factor holds hands no upstream tokens to a receiving client until the factor is proved.

## Depends on
- The package's scene builder, browser and fake upstream; `conformance-second-factor` (its area, TOTP codes and password browser)
