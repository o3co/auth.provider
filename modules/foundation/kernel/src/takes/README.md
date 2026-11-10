# takes

Internal module of `kernel`: the preflight of what modules take, before any factory runs.

## Responsibilities
- Checks each module's takes against what the modules provide and contribute, before anything is built, and answers the takes each module is held to while it is built.

## Not here
- Building, and refusing a take beyond the takes while a module is built (`building`). Reading sections and the duplicate providers (assembly's, refused with these at once).

## Offers
- `checkTakes` (modules, their checked sections, who provides and contributes, the refusals so far): each module's takes, held to the rest; `takenByRefusal` and `countRefusal`, the words a contract's `takenBy` and a point's rule refuse with, which assembly also speaks while it builds.

## Invariants
- A module without takes (one written past the types: plain JavaScript, or cast) is refused; `[]` names none.
- A function's takes are asked only with a section that passed its schema; one that throws refuses its module by name (`its takes failed as they were asked`), the thrown value's text never kept, and the other modules are still checked.
- Refused: a contract no other module provides (one the module provides itself is never named), one whose `takenBy` does not name the module, and a point whose registered contributions are too few or too many for its rule (`one`, `some`; a contribution that will fail as it builds counts), each point once by its identity, never its label. Duplicate keys at a `keyed` point are found once the contributions are built, not here.
- A `one` or `some` rule's `missing`, the words saying what to compose, follows its refusal when nothing is contributed, and only then.
- A point's handle carries its rule, whatever its contributions are.
- An optional take (`optional(contract)`) refuses no boot where no module provides its contract, and is held to its `takenBy`. Only a contract whose owner lets it go unprovided (`contract(label, { optional: true })`) may be taken so; any other refuses the boot (`<label> may not be taken optionally`).
- The owner's rule: a contract is let go unprovided only where a taker can answer "no module provides it" by failing closed (a feature read as off, a state as unknown, said at every start). A check, a fence, a guard, or any contract whose missing provider would weaken what a taker guarantees is never let go so: no module providing it refuses the boot.

## Depends on
- None; the package's handles, module definitions and refusals.
