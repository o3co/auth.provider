# takes

Internal module of `kernel`: the preflight of what modules take, before any factory runs.

## Responsibilities
- Checks each module's takes against what the modules provide and contribute, before anything is built, and answers the takes each module is held to while it is built.

## Not here
- Building, and refusing a take beyond the takes while a module is built (assembly's). Reading sections and the duplicate providers (assembly's, refused with these at once).

## Offers
- `checkTakes` (modules, their checked sections, who provides and contributes, the refusals so far): each module's takes, held to the rest; `takenByRefusal` and `countRefusal`, the words a contract's `takenBy` and a point's rule refuse with, which assembly also speaks while it builds.

## Invariants
- A module without takes (one written past the types: plain JavaScript, or cast) is refused; `[]` names none.
- A function's takes are asked only with a section that passed its schema; one that throws refuses its module by name (`its takes failed as they were asked`), the thrown value's text never kept, and the other modules are still checked.
- Refused: a contract no other module provides (one the module provides itself is never named), one whose `takenBy` does not name the module, and a point whose registered contributions are too few or too many for its rule (`one`, `some`; a contribution that will fail as it builds counts), each point once by its identity, never its label. Duplicate keys at a `keyed` point are found once the contributions are built, not here.
- A point's handle carries its rule, whatever its contributions are.

## Depends on
- None; the package's handles, module definitions and refusals.
