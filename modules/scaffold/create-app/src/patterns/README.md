# patterns

## Responsibilities
- Holds the patterns: each a deployment's use and the selection that composes it, in one file (`<name>.ts`) with a card of at most 10 lines (`<name>.md`).
- Merges the operator's choice into a pattern's selection, and says when its store keeps the deployment to one instance.

## Not here
- What a selection composes (needs, axes, wirings, bridges) and checking its names and kinds: `combinations`.
- The files generated and their configuration: `create-app`'s.
- Running the conformance areas against a pattern's app: the conformance base.

## Offers
- `patterns()`: each pattern's name, use, conformance areas and the features conformance adds for its run alone (a small reviewed list, so its core is under test), `full` last (the full template itself, with no file here).
- The pattern of a name, and its card without the title. A name not known is refused, naming those that are.
- `selectionOf(pattern, choice)`: the features every pattern composes, the pattern's groups with the operator's in their place, the pattern's axes under the operator's, and the features added.
- The groups: `login`, `second-factor`, `grants`, `client-auth`, `binding`.

## Invariants
- A pattern names only the features that decide its use; the foundations come with what needs them.
- A pattern writes no configuration value: its card names the keys the deployment provides for its use; what the store, users, audit and mail chosen ask is told from the modules composed (`chosen`), whatever the pattern's default.
- A group the operator names that is not one of the groups is refused, naming it.
- The memory store (`store` chosen as its own axis) means one instance.
- A pattern, and the full template, runs every conformance area whose module it composes.
- Module names are written here and in the operator's flags only.

## Depends on
- `combinations` (the selection's shape).
