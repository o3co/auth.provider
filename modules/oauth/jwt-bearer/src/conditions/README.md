# conditions

Internal module of `jwt-bearer`: the conditions an issuer holds an assertion's verified claims to, and whether claims meet them.

## Responsibilities
- Reads an issuer's conditions: a prefix of the verified `sub`, and claims each with its value or values.
- Answers whether verified claims meet every one.

## Not here
- Which issuer's conditions apply, and when they are asked (`issuers`, the package). Verifying the assertion (`assertion`).

## Offers
- `conditionsSetting`: `subject-prefix` (1 to 255 printable ASCII characters) and `claims` (a claim's name to a string, a number or a boolean, or a list of them one of which it holds).
- `meets` (conditions, verified claims) → whether every condition holds.

## Invariants
- Conditions hold one predicate at least: none written, an empty `claims`, a claim with an empty list, an empty prefix or a field it does not know is refused as written.
- A claim the grant's policy decides (`iss`, `aud`, `exp`, `nbf`, `iat`, `jti`) is never a condition; `sub` may be.
- Every predicate holds together. The prefix and values compare as written: by case, by kind (`"1"` is not `1`), with no trimming, decoding or Unicode normalization.
- A claim is read as the claims' own alone, never one an object holds by its kind; a claim that is a list or an object meets no value.

## Depends on
- `zod`
