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
- A function's takes are asked only with a section that passed its schema.
- Refused: a contract no other module provides (one the module provides itself is never named), one whose `takenBy` does not name the module, and a point whose registered contributions break its rule (a contribution that will fail as it builds counts), each point once by its identity, never its label.
- A point's handle carries its rule, whatever its contributions are.

## Depends on
- None; the package's handles, module definitions and refusals.
