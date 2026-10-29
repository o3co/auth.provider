# attack-surface

Internal module of `references`: the attack surface reference, what reaches the provider from outside and what it reaches out to.

## Responsibilities
- Generates `docs/attack-surface.md` from the full template with every opt-in: the packages it leaves out, its routes (the `HEAD` and preflight `OPTIONS` `http` answers beside them, `GET`s that change state, other sites' and uncounted routes, browser redirects), what reaches out (`network`, `outbound`'s dependents, `internalBy`, destination settings), secrets in settings, settings that weaken a guarantee, and the operator's manual tasks.
- Holds the hand-written coverage (`coverage.ts`): what no module declares, each entry with why.

## Not here
- What a route, setting or package does: its own card. Which routes `http` serves: the route reference.
- Secrets kept in stores: each module's card, under Data.

## Offers
- `attackSurfaceIn` (root) → what the reference is made from; `attackSurfaceOf` → the reference; `attackSurfaceFile`.
- The naming rules: `secretByName` (a last segment that names a secret, or ends in one), `looseningByName` (`accept-*`, `insecure-*`, `fail-mode`, `on-unavailable`, `durability`, `replication`, `subject-check`), `looseningCandidate`, `destinationCandidate` (a last segment holding `host`, `api`, `issuer`, `server` or `discovery`), `destinationByName`; `answersHead` (a `GET` that does not change state).

## Invariants
- The reference is one composition on its defaults, and says so; a list is what modules declare, never a proof.
- Every setting the candidate rule or the security model names as a choice (written with a value, or under "Left to you") is classified: by a naming rule, or in the coverage as weakening or not, secret or not.
- Every setting the destination candidate rule names is classified: by `destinationByName`, or in the coverage as naming a destination or not.
- Every setting, route and runbook section the coverage names is in the workspace.

## Depends on
- The package's configuration rows, route reading and workspace list; `combinations` (the full template and its opt-ins).
