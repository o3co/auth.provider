# added-claims

Internal module of `tokens`: the rules of the claims a grant adds to its access token, and the one checker that copies them at issue and when a token is read back.

## Responsibilities
- Checks a grant's added claims and copies them into a new frozen record, or refuses them: the same at `issue`, at `admits` and when a verified payload is read back.

## Not here
- Writing them into the payload, signing, and reading a token: the package's.

## Offers
- `AddedClaims`, `AddedValue`: JSON values by name.
- `addedClaimsOf` (what a grant gives) → the frozen copy, none for none or an empty set; throws TypeError on anything outside the rules.
- `addedClaimsIn` (a verified payload) → its members `tokens` does not write, for `addedClaimsOf` to check.
- `reserved`, `unwritten`, `limits`.

## Invariants
- Reserved at the top: every name `tokens` writes (`iss`, `sub`, `aud`, `client_id`, `scope`, `act`, `amr`, `auth_time`, `acr`, `iat`, `exp`, `jti`, `cnf`).
- Reserved at the top too: names a specification gives a meaning `tokens` never writes (`nbf`, `roles`, `groups`, `entitlements`, `scp`, `may_act`, `authorization_details`, `htm`, `htu`, `ath`, `nonce`, `azp`, `at_hash`, `c_hash`, `sid`, `name`, `picture`, `profile`, `email`, `email_verified`, `active`, `token_type`, `username`). A read-back token holding one of the latter is none of `tokens`'.
- `__proto__`, `constructor` and `prototype` are refused as a key at any depth.
- Only JSON is taken: plain objects (the object prototype or none) and arrays with no hole or other property, strings, finite numbers, booleans and null; their own enumerable data properties alone are read.
- Refused without calling anything given: an accessor, a proxy, a cycle, a prototype of its own, a function, a symbol as a key or a value, a bigint, undefined, a number not finite.
- A name is 1 to 255 code points, well formed, with no control character or space; a string is at most 2048 code points, well formed.
- At most 256 members to an object or values to an array, 1024 values in all, 8 deep (a claim's value is depth 1), and 4 KiB as JSON in UTF-8. Each limit is counted while walking, so a large set stops at the first one it passes.

## Depends on
- Node's `util` (to tell a proxy).
