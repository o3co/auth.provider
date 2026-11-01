# endpoint-in

Internal module of `token-endpoint`: the endpoint's handler, built over what the assembly gives.

## Responsibilities
- Takes the contracts the handler works over from the assembly, and the grants composed by type, and builds the handler.

## Not here
- Handling a request, from the request to the answer (`route`). Which grants are composed, and the route's declaration (the package's module).

## Offers
- `endpointIn` (the build context, the grants composed) → `route`'s handler over `clients`, `tokens`, `grants`' session issuances and audience rule, `sender-binding`'s readers and required bindings, and `audit`.

## Invariants
- A grant is found by its grant type; nothing else is decided here.

## Depends on
- `kernel` (the build context), `audit`, `clients`, `grants`, `sender-binding`, `tokens`; `route`'s handler.
