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
- The owner is the package whose manifest declares `internalBy`, a list of package names; its contract exports the interface `Narrower`, whose `internal` property gives the type counted.
- Counted: an object literal's property named `internal`, written as a property, a shorthand or a computed string key, anywhere in shipped code, whose value, `undefined` aside, is of that type. A binding, a property of another type, a value of type `any`, `unknown` or `never`, and a test are not.
- A package outside the list writing one is reported at its file and line, never with the value; so is a listed name that is no workspace package, that writes none, or that is listed twice, and a list that is no list.

## Depends on
- `typescript` (its type checker, over the workspace's packages by name).
