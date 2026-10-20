# held

Internal module of `conformance-federation`: the scenes of a federation login that a gate holds.

## Responsibilities
- Checks that a login through an upstream that the user's second factor holds hands no upstream tokens to a receiving client until the factor is proved.
- Checks that a held login goes to the held page by 303 with no query, where the page reads it by the browser's cookies alone and binds or proves the factor.
- Checks that a proved login lands where it asked, else at the landing, else at the origin's root.
- Checks that, without a held page, a held login is answered 403 with the gate's answer.

## Depends on
- The package's scene builder, browser and fake upstream; `conformance-second-factor` (its area and TOTP codes)
