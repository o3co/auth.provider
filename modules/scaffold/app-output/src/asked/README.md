# asked

Internal module of `app-output`: what each composed module asks of the deployment, as its manifest declares it, rendered for the guide.

## Responsibilities
- Renders the guide's two lists from the modules' declarations: what the composition asks of the deployment, and the values the operator decides.

## Not here
- What each line says: the module's own, in its manifest. Which modules are composed, and where the lists go in a template: the caller's.

## Offers
- `askedOf` (the modules composed, in order; what each declares, `Asked`) → the two lists, each line as `- …`.
- `Ask`, a line: a string, or `{ line, decides?, unadapted? }`. `Asked`: a package's lines (`asks`), the owner it adapts (`adapts`) and the name it registers under its owner (`registersAs`).

## Invariants
- Lines come in the modules' order, each module's in its own order; a line marked `decides` goes in the values the operator decides, the others in what the composition asks.
- A line marked `unadapted` is left out where an adapter of its module (`adapts` it) is composed.
- `{adapters}`, the one mark a line may hold, is the composed adapters' `registersAs` names, joined by `, `, or, where none is composed, the module's own.
- A declaration of a module not composed is read as none; it names no module of its own, only what a declaration says.

## Depends on
- Nothing beyond the declarations given.
