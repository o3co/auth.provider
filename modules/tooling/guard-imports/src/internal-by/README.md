# internal-by

Internal module of `guard-imports`: G32, that the property an owner holds to declaration (the narrower's `internal`) is written only by the packages declaring it.

## Responsibilities
- Reads the owner's `narrower`, the type and property it holds to declaration, and each other manifest's `narrower`, the property a package declares it writes; holds every package's shipped code to them. While `internalBy` is read beside them, a package its list names may write the property too.

## Not here
- What `internal` lets a request reach: the owner's (outbound-policy's). Who declares it: each package, by review.
- Values made to look like an operator's URL: another rule's.

## Offers
- `internalByRules` (G32).

## Invariants
- The owner is the one package whose `narrower` is `{ type, property }` (or, while it is read, whose manifest has `internalBy`, for `Narrower` and `internal`); its contract exports that type (declared there or re-exported), whose property gives the type counted. The owner's own code is held to it too: it states the property, and writes none.
- A writer declares `narrower` as exactly the property's name, a string, and its card states it as `` `narrower`: `internal` ``.
- Counted: an object literal's property of the owned property's name, anywhere in shipped code, a literal spread into another included, whose value, `undefined` aside, is of that type: a property, a shorthand, a getter (its return), or a computed key whose type that name fits (a union, a template, a mapped string such as `Lowercase<string>`, or a string of no known value), or whose type holds a type parameter anywhere, whatever it is bound to or narrowed by. Any other key is not counted.
- Not counted: a binding, a property of another type, a value of type `any`, `unknown` or `never`, a test; a literal whose value is a type parameter (a generic factory's, though called with that type) and an object only spread on, its own literal counted where written.
- A package neither declaring nor listed writing one is reported at its file and line, never with the value. So are: a declaration that writes none, is not exactly the property, or is not stated on the card; a declaration with no owner, or two owners; an owner's `narrower` naming no type and property; and, while `internalBy` is read, a listed name that is no workspace package, that writes none, or that is listed twice, and a list that is no list.

## Depends on
- `typescript` (its type checker, over the workspace's packages by name).
