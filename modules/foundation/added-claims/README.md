# added-claims

## Responsibilities
- Owns the rules of the claims a grant adds to its access token, their shape, the names reserved and the limits, and the one walker that checks a set of them and copies it.

## Not here
- Writing them into a token, signing, reading a token back, and when either happens: `tokens`'.

## Offers
- `AddedClaims`, `AddedValue`: JSON values by name; `AddedClaims` lists every reserved name.
- `addedClaimsLimits`, the schema part `tokens`' section takes as `added-claims`: the limits an operator may raise, each from today's value (`name-length`, `string-length`, `members`, `values`, `depth`, `size`).
- `addedClaimsWith` (the limits read) → `of` and `readBack`, as below, under them; `addedClaimsOf` and `addedClaimsReadBack` are those under the defaults.
- `addedClaimsOf` (what a grant gives) → a new frozen copy within the rules, none for none or an empty set; throws TypeError, naming the rule, and a null's path, on anything outside them.
- `addedClaimsIn` (a verified payload) → its members an access token's issuer does not write, for `addedClaimsReadBack` to check.
- `addedClaimsReadBack` (those members) → as `addedClaimsOf` answers, but a null is taken: a token an earlier release signed may hold one.

## Invariants
- An added claim is JSON alone: plain objects (the object prototype or none), arrays with no hole or other property, strings, finite numbers and booleans. A null, at any depth, is refused, as signing refuses it: leave the member out.
- Only own enumerable data properties are read, and an array's own `length`; nothing given is called. An accessor, a proxy, a cycle, a prototype of its own, a function, a symbol, a bigint or undefined is refused.
- Reserved at the top: every name an access token's issuer writes, and names a specification gives a meaning it never writes. A payload read back holding one of the latter is none the issuer wrote.
- Never a key at any depth: `__proto__`, `constructor`, `prototype` and `toJSON`.
- A name is 1 to `name-length` code points (255 unless raised), well formed (no lone surrogate), with no control character or space; a string is at most `string-length` code points (2048), well formed.
- At most `members` members to an object or values to an array (256), `values` values in all (1024), `depth` deep (8; a claim's value is depth 1), and `size` as JSON in UTF-8 (4 KiB).
- One set of limits holds a grant's claims and a token's read back: lowering a raised one leaves the tokens issued while it was raised unreadable until their `exp`.
- A set stops at the first limit it passes: a count is taken before what it counts is read, and a string or a name past twice its limit is refused unread.
- The copy is frozen at every depth; what was given is never used past it.

## Depends on
- Node's `util` (to tell a proxy); `kernel` (`setting`, a size's unit).

## Vocabulary
- added claim: a member a grant adds to the access token it issues, by name.
- reserved name: one no added claim may take.
