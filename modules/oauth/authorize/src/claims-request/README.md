# claims-request

Internal module of `authorize`: reading the `claims` request parameter (OpenID Connect Core §5.5).

## Responsibilities
- Parses `claims` once, as JSON, and reads what `authorize` acts on: the acr each of its `id_token` and `userinfo` members asks for, and whether `id_token` asks for an essential `auth_time`.

## Not here
- What the acr asked means for the code (`step-up`).

## Offers
- `claimsAsked` (the parameter's text → the acr each member asks, kept apart, and whether a known authentication time is essential; or malformed)

## Invariants
- A parameter that is not a JSON object, or an `acr` of no shape Core §5.5.1 gives (`null`, or `essential` a boolean, `value` a string, `values` a non-empty list of strings, not both), is malformed.
- The other claims it names are not read here.

## Depends on
- Nothing beyond the language.
