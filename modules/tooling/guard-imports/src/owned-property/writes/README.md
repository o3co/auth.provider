# writes

Internal module of `owned-property`: where a source writes the owned property, by type in a source and by name in a template.

## Responsibilities
- Finds each write of the property in one source file, and judges it as the reading it is given says.

## Not here
- Which property is owned, its type, and which packages may write it (`owned-property`).
- Building the program the types come from (`owned-property`).

## Offers
- `writesIn` (a source, a reading → the lines it writes the property on).
- `typedReading` (checker, the property's type, its name → the reading of a source), `byNameReading` (its name → the reading of a template); `Reading`.
- `isTemplate`: whether a file is a template of a source (`main.ts.template`, `guard.ts.part`: a `.ts` or `.mjs` name under a suffix of its own).

## Invariants
- A write: an object literal's property of the owned name, a literal spread into another included: a property, a shorthand, a getter (its return), or a computed key whose type that name fits (a union, a template, a mapped string such as `Lowercase<string>`, or a string of no known value). Any other key is not counted.
- A write too: an access to the property that is written to, directly (`n.internal = …`, `n["internal"] = …`, `??=`, `||=`, `&&=`), as a `for … of` or `for … in` head, or as a destructuring pattern's target (renamed, nested or in an array: `({ url: n.internal } = s)`, `[n.internal] = v`); a class field initialised under its name; a constructor's parameter property of that name.
- A destructuring pattern is no object literal: its own keys write locals, so `({ internal } = s)` writes nothing of the property.
- Typed, a write counts where what it writes, `undefined` aside, may be of the property's type: a literal's value, a target's own type (and a direct assignment's value), a field's initializer. A value of type `any`, `unknown` or `never` does not count.
- A type parameter is read by what it may be bound to, its constraint (unknown for a bare one): a key holding one counts where the owned name fits it, a value holding one where the property's type does. A generic helper's write is counted at the helper, whoever calls it.
- By name, every form above counts whatever it writes, a template's imports being filled in only when it is written out; a computed key or an element access counts unless it is a literal of another name.

## Depends on
- `typescript` (its syntax and type checker).
