# protocol

Internal module of `guard`: G33, a protocol package holds a wire's contract alone.

## Responsibilities
- Holds a package of the protocol kind to what a wire's contract is (types, constants, fixed schemas and the functions that build by them), by what it may reach rather than by a list of what it may not.

## Not here
- Whether its words are a wire's and nothing more, whether a constant is frozen, whether a function or a zod refinement only validates: review judges what the syntax does not show, and a form written to slip past these rules, as for G26.
- The kind's place in the order (the bottom level, depending on nothing: G2) and its names (G6).

## Offers
- `protocolRules` (G33).

## Invariants
- Its manifest exports `.` alone, and declares no `network` word nor `forks`.
- It reads each file's `facts`. Its shipped code imports at run time (every edge that loads its module, `import { type T }` too) `zod` and files alone; where a file is, within the package or not, is G34's, for every package. An import of a type alone may name anything.
- It loads no module at run time (`import()`, however its name is written; `require` is a global refused) and reads no `import.meta`.
- `import.meta` and the top level's statements are read from the file's syntax here, being no fact. A second rule reading a form facts do not hold moves it into `facts`.
- A name in a value's role that `facts` find unbound is a global, and only these are reached: `Object`, `Array`, `String`, `Number`, `Boolean`, `JSON`, `Symbol`, `RegExp`, `Error`, `TypeError`, `RangeError`, `undefined`, `NaN`, `Infinity`. Any other, `globalThis` and `require` among them, is refused wherever it stands, inside a function or a constant's initializer alike.
- What a value's role is, as `facts` read it: a class's `extends` expression and an instantiation (`f<T>`) are values, their type arguments, `implements`, a property's or a declaration's name and an import attribute's key not; a shorthand property and a local export are read by the value they name; a name bound in the file (`process` declared there too) is no global.
- Each file's top level holds imports (an `import type … = require(…)` alias too; an alias of a value loads as the file loads), exports (`export default` too, its value read as any), types, interfaces, functions and `const` declarations alone; a `let`, a `var`, a class or any other statement (one run as the file loads) is refused.
- Tests are not read, so its shipped code loads no test file of its own (a type from one loads nothing).

## Depends on
- `guard-imports` (the package as read, each file's `facts`), `typescript` (the file's syntax).
