# owned-property

Internal module of `guard-imports`: G32, that the property an owner holds to declaration (the narrower's `internal`) is written only by the packages declaring it.

## Responsibilities
- Reads the owner's `narrowerOwner`, the type and property it holds to declaration, and each other manifest's `narrower`, the property a package declares it writes; holds every package's shipped code to them.

## Not here
- What `internal` lets a request reach: the owner's (outbound-policy's). Who declares it: each package, by review.
- Values made to look like an operator's URL: another rule's.
- The runtime guarantee: `outbound-policy`'s, as a private address is reached only at the origin of the `ConfiguredUrl` a caller names. G32 is the check of it in this repository: that the code it reads does not write the property undeclared.
- A value widened before it is written, as the check goes by type: one cast or typed as `any`, `unknown` or plain `string` first (`{ internal: url as any }`; `const t: string = url`, then `{ internal: t }`). Copies from a typed object (`Object.assign`, spreading a typed value), counted where that object's own literal is written, not at the copy. Reflection (`Object.defineProperty`, `Reflect.set`).
- What it does not read: test files (the rules' `testFile`), a package's `./testing` entry, `*.config.ts`, files and directories whose name starts with `.`, `node_modules`, and any package pnpm does not list, though shipped code may import one of them.

## Offers
- `ownedPropertyRules` (G32).
- `propertyDeclarations` (packages → what their manifests state: the owners' `narrowerOwner`, those naming no type and property, the packages declaring `narrower`, and the writers among them, those declaring exactly the one owner's property, none where there is no owner or two), so every reader reads and judges the convention once; `PropertyDeclarations`, `Owned`.

## Invariants
- The owner is the one package whose `narrowerOwner` is `{ type, property }`; its contract exports that type (declared there or re-exported), whose property gives the type counted. The owner's own code is held to it too: it states the property, and writes none.
- The workspace's rules say how many packages must state what they hold to declaration (`declaredProperties`); fewer are refused, so removing an owner's statement never leaves its writes unchecked. Unset, none is asked.
- A writer declares `narrower` as exactly the property's name, a string, and its card states it as `` `narrower`: `internal` ``.
- Counted: each write `writes` finds in shipped `.ts` and `.mjs` code, by type, and in a template, by name.
- A package not declaring it writing one is reported at its file and line, never with the value. So are: a declaration that writes none, is not exactly the property, or is not stated on the card; a declaration with no owner, or two owners; and an owner's `narrowerOwner` naming no type and property.

## Depends on
- `typescript` (its type checker, over the workspace's packages by name).
- Internal module `writes`.
