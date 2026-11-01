# returns

Internal module of `login-gates`: where a login may send the browser back to.

## Responsibilities
- Judges a return target against what the operator wrote and the paths modules contribute, at the public origin.

## Offers
- `returnsWith` (the operator's `return-targets`, the public origin, the contributed `returnPaths`, the builder's `refuse`) → `returnAllowed` (a target).

## Invariants
- A target is judged as written: one holding a space or a control character, or a fragment, is refused, as is one the URL parser would rewrite on the way (dot segments, backslashes), or one with userinfo, a port or another origin.
- A target the operator wrote is taken as written; a contributed path only at the public origin, to its query.
- A path below a parent contributed with a segment is one name segment of letters, digits, `_` and `-` (1 to 64), never empty, a dot or encoded.
- A parent taking a segment is a path below the root, beginning with a slash and not ending in one; any other refuses boot, naming it.

## Depends on
- The contract's `ReturnPath`.
