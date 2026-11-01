# facts

Internal module of `guard-imports`: what each source file says, read by one lexical program per run for the rules that read syntax: the modules it reaches and where each leads, and what each name it uses is bound to and stands for.

## Responsibilities
- Reads the scanned files (`.ts`, declaration files too, and `.mjs`) in one lexical program, each file's facts once, and answers them; each rule applies its own policy.

## Not here
- Any rule's policy: which modules, names or forms are allowed, and whether an unresolved edge is refused or let through.
- What the syntax does not show: dataflow and effects, a dependency's behaviour, prototype or reflection tricks, custom loaders, file-system races. Guard holds our own code to its design, written the ordinary way; it confines no hostile code.
- Semantic resolution across files (a signature's declaration, a contract's type): the readers that build programs of their own (`surface`, `recorded`, `owned-property`).
- A package's exports map: a bare specifier is a package and its subpath, unresolved further.

## Offers
- `lexicalAnalysis` (the scanned files) → `factsOf` (a file): its syntax tree and the program's checker, for a reader that reads more; its edges; its references; its member reads.
- An edge (`Edge`): its form (`import`, `export-from`, `dynamic-import`, `import-type`, `import-equals`, `require`, `resolve`), where it is written, its specifier (or the static part of one named at run time), whether it loads the module, its loader (`require` unbound or one `createRequire` made), its bindings and its target.
- A binding (`EdgeBinding`): its form (`default`, `named`, `namespace`, `star`, `equals`, `whole`, `destructured`), the name taken from the module, the local name, the name a re-export gives, and its own type-only.
- A target (`Target`): `builtin`, `package` (name, subpath), `file` (its runtime URL, the query and fragment kept as identity, and its real path) or `unresolved` (`computed`, `private-import`, `scheme`, `missing`, `unsupported`, with the static fragment or the path it would have).
- A reference (`Reference`): an identifier, its role (`value`, `type`, `type-query`, `declared`, `property`, `attribute-key`, `label`) and, but for the last three, its binding: `local` (the declaration), `imported` (the edge and the name taken) or `unbound` (the name alone).
- A member read (`MemberRead`): a property of a name read by a dot or a literal key, unnamed where computed.
- `roleOf`, `valueWithTypeArguments`, `loaderOf`, and the resolvers `esmTarget`, `requireTarget`, `packageOf`, `realOf`.

## Invariants
- One lexical program: no lib, every file a module (no script's globals reach another file), and a host that reads the scanned files alone and resolves no module or type reference. `unbound` means no binding in the file's lexical scope, never a host global confirmed; which names a rule allows is the rule's.
- Loads and binds apart, under `verbatimModuleSyntax`:
  - `import { type T } from "m"` binds a type and loads `m`; `import {} from "m"`, `import "m"` and `export {} from "m"` load it and bind nothing.
  - `import type`, `export type`, `import type … = require`, an import type and a resolve load nothing, nor does any edge in an ambient context.
- Specifiers resolve as Node's loaders read them:
  - ESM: a URL from the importing file's real path, encoded dots climbing, a query and a fragment no part of the path yet kept in the URL. A file as named alone: a directory, and a URL Node cannot read as a path (another host, an encoded slash), are `unsupported`.
  - `require`: a path from its loader's base: a module's own from its real place, `createRequire`'s from what it was given, as given and unfollowed (a directory itself where it ends in `/`, else a file's), `unsupported` where that is not known. Nothing decoded, a `?` part of the name; the file, with `.js`, `.json` or `.node`, then a directory's `package.json` `main`, then its `index` of those; a specifier ending in `/`, or in a `.` or `..` segment, names the directory alone.
  - Links followed on both sides; a path given or asked in any spelling is the one absolute path.
- A specifier named at run time is an `unresolved` edge, never dropped; `#…`, a scheme but `node:` and `file:`, and a file not on disk are unresolved too.
- What reads as a value:
  - A shorthand property (by its own name, never its default's) and a local export read the value they name.
  - In an ambient context nothing runs: a value's place is a type's.
- One test tells an ambient context, for edges and names alike: a declaration file, or anywhere inside a declaration marked `declare` (a class, a function, a variable, a module, a namespace, an enum).
  - A class's `extends` and an instantiation (`f<T>`) are values; `implements` and an interface's `extends` are types.
  - `typeof x` in a type is a lookup, not a run.
  - An import attribute's key is syntax.
- A loader is `require` unbound in its own file (another file's declaration binds nothing here), or a name bound to what `createRequire` from `node:module` made; its result named whole or taken apart, by a name or a quoted one, binds those names, and a rest (`...rest`) binds the module whole. A local named `require` otherwise is no loader. `import.meta.resolve` and a loader's `resolve` are resolves; `new URL` and a `Worker` are no edge.
- JSX, `.cts`, `.cjs` and `.mts` are not read: asking for one refuses.

## Depends on
- `typescript`; Node's `fs`, `module`, `path` and `url` (real paths, built-in names, resolution).
