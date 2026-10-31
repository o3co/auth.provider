# building

Internal module of `kernel`: building the provisions and contributions, each once, and the build context each factory sees.

## Responsibilities
- Builds an item on request with its build context, caching it for every later request; refuses a cycle, a contract no module provides, a take beyond the module's takes and one a contract's `takenBy` does not name, each recorded even where the taker catches the throw.

## Not here
- The takes' preflight (`takes`). Reading sections and the duplicate providers, the order the stages build in, checking late references and refusing the boot (the package's assembly). Running the hooks and the periodic tasks (`lifecycle`).

## Offers
- `buildingWith` (the runtime, the environment, the checked sections, who provides and contributes, the takes each module is held to, the refusals, a test's watch) → `build` (an item, the stack of builds asking it), the points collected with their checks' outcomes, the late references named, the contracts built, the hooks and periodic tasks registered, and `assembledWith` (readiness), from which late references and readiness answer.
- `checkPoint`: freezes a point's contributions one level and checks its rule (count, and duplicate keys at a `keyed` point). `recordFailure`: records why a build failed, unless the refusal behind it is recorded already. `Buildable`, `TakesWatch`.

## Invariants
- An item is built once, by whichever request comes first; a request from a build that the item waits on, directly or across branches, is a cycle, refused before the cache is joined.
- A point is checked once, however many modules collect it: one refusal for a break.
- A factory's thrown value is read as a refusal only where it is one; any other error's text is never kept.
- The build context's `environment` cannot be written or redefined by a factory.

## Depends on
- None; the package's handles, module definitions, refusals, runtime, `lifecycle` (periodic tasks, the interval rule) and `takes` (the words a `takenBy` and a point's rule refuse with).
