# internal-by

Internal module of `guard-imports`: G32, that the narrower's `internal` is written by the packages its owner lists alone.

## Responsibilities
- Reads each manifest's `internalBy` (the packages that may write `internal`), and holds every other package's shipped code to it.

## Not here
- What `internal` lets a request reach, and who may be listed: the owner's (outbound-policy's), by review.
- Values made to look like an operator's URL: another rule's.

## Offers
- `internalByRules` (G32).

## Invariants
- The owner is the package whose manifest declares `internalBy`, a list of package names; its contract exports `Narrower` (declared there or re-exported), whose `internal` property gives the type counted. The owner's own code is held to the list too: it states `internal`, and writes none.
- Counted: an object literal's property named `internal`, anywhere in shipped code, a literal spread into another included, whose value, `undefined` aside, is of that type: a property, a shorthand, a getter (its return), or a computed key whose type the string `"internal"` fits (a union, a template, a mapped string such as `Lowercase<string>`, or a string of no known value), or whose type holds a type parameter anywhere, whatever it is bound to or narrowed by. Any other key is not counted.
- Not counted: a binding, a property of another type, a value of type `any`, `unknown` or `never`, a test; a literal whose value is a type parameter (a generic factory's, though called with that type) and an object only spread on, its own literal counted where written.
- A package outside the list writing one is reported at its file and line, never with the value; so is a listed name that is no workspace package, that writes none, or that is listed twice, and a list that is no list.

## Depends on
- `typescript` (its type checker, over the workspace's packages by name).
