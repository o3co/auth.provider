# added-claims

## Responsibilities
- Owns the rules of the claims a grant adds to its access token, their shape, the names reserved and the limits, and the one walker that checks a set of them and copies it.

## Not here
- Writing them into a token, signing, reading a token back, and when either happens: `tokens`'.

## Offers
- `AddedClaims`, `AddedValue`: JSON values by name; `AddedClaims` lists every reserved name.
- `addedClaimsOf` (what a grant gives) → a new frozen copy within the rules, none for none or an empty set; throws TypeError, naming the rule, on anything outside them.
- `addedClaimsIn` (a verified payload) → its members an access token's issuer does not write, for `addedClaimsOf` to check.

## Invariants
- An added claim is JSON alone: plain objects (the object prototype or none), arrays with no hole or other property, strings, finite numbers, booleans and null.
- Only own enumerable data properties are read, and an array's own `length`; nothing given is called. An accessor, a proxy, a cycle, a prototype of its own, a function, a symbol, a bigint or undefined is refused.
- Reserved at the top: every name an access token's issuer writes (`aud_added`, how many of the last `aud` values it added, among them), and names a specification gives a meaning it never writes. A payload read back holding one of the latter is none the issuer wrote.
- Never a key at any depth: `__proto__`, `constructor`, `prototype` and `toJSON`.
- A name is 1–255 code points, well formed (no lone surrogate), with no control character or space; a string is at most 2048 code points, well formed.
- At most 256 members to an object or values to an array, 1024 values in all, 8 deep (a claim's value is depth 1), and 4 KiB as JSON in UTF-8.
- A set stops at the first limit it passes: a count is taken before what it counts is read, and a string or a name past twice its limit is refused unread.
- The copy is frozen at every depth; what was given is never used past it.

## Depends on
- Node's `util` (to tell a proxy).

## Vocabulary
- added claim: a member a grant adds to the access token it issues, by name.
- reserved name: one no added claim may take.
