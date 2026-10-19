# wiring

Internal module of `mfa-flows`: what each of the package's internal modules is given, and the lockout policy from the section.

## Responsibilities
- Pulls the contracts the assembly gives and hands each internal module only the interfaces it uses.

## Not here
- The routes and their policies (the package's module). What each internal module does (its own card).

## Offers
- `handlersOver` (the build context, the lockout policy) → every route's handler, by name.
- `policyOf` (the section) → the lockout policy `rate-limit` judges.
- `partsIn` (the build context) → the parts the module binding factors takes (`seams`).

## Invariants
- Internal modules: `transactions` keeps transactions; `proof` holds a login (the gate) or a session (step-up) until a factor is proved; `enrollment` binds a new factor; `reset` is the operator's reset; `release` the user's, by `permits`; `recording` records a request's audit events; `seams` shapes what the module binding factors gives and takes. `transactions` takes its own contracts; `wiring` gives the others only what they use.
- The enrollment routes and an enrollment's challenge go to the flow contributed to `enrollmentFlow`, else to `enrollment`.

## Depends on
- `kernel` (the build context); `audit`, `login-gates`, `mfa`, `mfa-binding-proof`, `rate-limit`, `session`, `subject-revocation` (the contracts it hands on); the package's contract (`enrollmentFlow`), internal modules, section and store interfaces.
