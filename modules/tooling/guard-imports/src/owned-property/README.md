# owned-property

Internal module of `guard-imports`: G32, that the property an owner holds to declaration (the narrower's `internal`) is written only by the packages declaring it.

## Responsibilities
- Reads the owner's `narrower`, the type and property it holds to declaration, and each other manifest's `narrower`, the property a package declares it writes; holds every package's shipped code to them.

## Not here
- What `internal` lets a request reach: the owner's (outbound-policy's). Who declares it: each package, by review.
- Values made to look like an operator's URL: another rule's.

## Offers
- `ownedPropertyRules` (G32).

## Invariants
- The owner is the one package whose `narrower` is `{ type, property }`; its contract exports that type (declared there or re-exported), whose property gives the type counted. The owner's own code is held to it too: it states the property, and writes none.
- The workspace's rules say how many packages must state what they hold to declaration (`declaredProperties`); fewer are refused, so removing an owner's statement never leaves its writes unchecked. Unset, none is asked.
- A writer declares `narrower` as exactly the property's name, a string, and its card states it as `` `narrower`: `internal` ``.
- Counted: an object literal's property of the owned property's name, anywhere in shipped `.ts` and `.mjs` code, a literal spread into another included, whose value, `undefined` aside, is of that type: a property, a shorthand, a getter (its return), or a computed key whose type that name fits (a union, a template, a mapped string such as `Lowercase<string>`, or a string of no known value). Any other key is not counted.
- Counted too, by the same rule: an assignment to the property (`n.internal = …`, `n["internal"] = …`, `??=`, `||=` and `&&=` alike), a class field initialised under its name, and a constructor's parameter property of that name.
- A type parameter is read by what it may be bound to, its constraint (unknown for a bare one): a key holding one counts where the owned name fits it, a value holding one where the property's type does. A generic helper's write is counted at the helper, whoever calls it.
- A template of a source (`main.ts.template`, `guard.ts.part`: a `.ts` or `.mjs` name under a suffix of its own) is read by name alone, its imports being filled in when it is written out: a property of the owned name counts whatever its value, and so does a computed key that is no literal of another name.
- Not counted: a binding, a property of another type, a value of type `any`, `unknown` or `never`, a test, and an object only spread on, its own literal counted where written.
- A package not declaring it writing one is reported at its file and line, never with the value. So are: a declaration that writes none, is not exactly the property, or is not stated on the card; a declaration with no owner, or two owners; and an owner's `narrower` naming no type and property.

## Limits
- What G32 promises is that the code it reads does not write the property undeclared. The runtime guarantee is `outbound-policy`'s: a private address is reached only at the origin of the `ConfiguredUrl` a caller names; G32 is the check of that in this repository.
- It goes by type, so a value widened before it is written is not seen: one cast or typed as `any`, `unknown` or plain `string` first (`{ internal: url as any }`; `const t: string = url`, then `{ internal: t }`). Reflection (`Object.defineProperty`, `Reflect.set`) is not read either.
- It reads the sources the workspace's packages hold, as pnpm lists them: each package's `.ts` (but `*.config.ts`) and `.mjs` files and its templates. Not read: test files (the rules' `testFile`), a package's `./testing` entry, `*.config.ts`, files and directories whose name starts with `.`, `node_modules`, and any package pnpm does not list, though shipped code may import one of them.

## Depends on
- `typescript` (its type checker, over the workspace's packages by name).
