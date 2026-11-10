# surface

Internal module of `guard-imports`: a package's public surface, read from one of its entries by a TypeScript program of its own.

## Responsibilities
- Reads what an entry exports: values and types, the contracts and extension points among them (made by the kernel's `contract` or `extensionPoint`), the members of exported interfaces and type aliases, the types a public signature uses that the entry does not export, the doc comments on exported declarations and their members, each export's signature, and what each export carries.

## Not here
- Which rules read the surface (`guard-imports`' rules, `guard`'s budget) and what they make of it.
- What a source file says by its syntax alone: `facts`.

## Offers
- `surfaceOf` (entry, package directory) → `Surface`: `values`, `types`, `hidden`, `members`, `tokens`, `points`, `docs`, `signatures` and `carries` (each export → the exported types its signature names, one step, by symbol; a value's inferred type too).

## Invariants
- A signature is the export's structure as text: a type's members, each with `readonly`, optionality and its type, sorted by name, with its calls, constructions and index signatures; a type's parameters as written; a value's type; an enum's members and their values.
- Two surfaces' signatures differ wherever their contract does: a member's type, one member put in another's place, a member made optional, a type parameter's bound. They are the same wherever a declaration only moves to another file of the package. A type a signature names by name has its own signature, or is `hidden`.
- A member keyed by a symbol is named as written (`[mark]`, `[Symbol.iterator]`), never by the id the checker gives it, so two programs over the same contract write the same signature.
- A primitive, or a union of them, counts no members: the platform's own are not the contract's.
- Only declarations inside the package count: none from `node_modules` or another package.
- An export carries the types the entry exports that its signature names, one step, by symbol (an alias the printer expands, and a re-export under another name, as the entry exports it). A value's inferred type counts too, read through its unions, calls and anonymous members up to a named type; a type outside the package is read at its arguments alone. The same walk names the rest of the package's types `hidden`.
- Every program parses through one host: a parsed file is reused only while its text is the same. Every program shares the same compiler options.

## Depends on
- `typescript`.
