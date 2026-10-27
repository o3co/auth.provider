# claims-request

Internal module of `authorize`: reading the `claims` request parameter (OpenID Connect Core §5.5).

## Responsibilities
- Parses `claims` once, as JSON, and reads what `authorize` acts on: the acr and the `sub` values each of its `id_token` and `userinfo` members asks for, whether `id_token` asks for an essential `auth_time`, and, given each claim's scope, the claims each names beyond the scope with their constraints.

## Not here
- What the acr asked means for the code (`step-up`). Which scope a claim belongs to, and selecting the names (`claims-selection`).

## Offers
- `claimsAsked` (the parameter's text, optionally each claim's scope, and whether the request is OpenID Connect's, without which no `sub` is read or judged → the acr and `sub` values each member asks, kept apart, whether a known authentication time is essential, and the selection asked; or malformed), `noClaims`

## Invariants
- A parameter that is not a JSON object, or an `acr` or `sub` of no shape Core §5.5.1 gives (`null`, or `essential` a boolean, `value` a string, `values` a non-empty list of strings, not both), is malformed.
- A claim with a scope is held to the bounds `claims-selection` keeps: `value` or up to 16 `values` of scalars, a string up to 256 characters, the whole within `withinLimits`; another is malformed. A claim without a scope, and a member of a claim request it does not read, are passed over (Core §5.5.1).

## Depends on
- `claims-selection` (the selection's types and bounds)
