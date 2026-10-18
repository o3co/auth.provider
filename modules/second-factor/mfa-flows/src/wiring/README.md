# wiring

Internal module of `mfa-flows`: what each of the package's internal modules is given, and the lockout policy from the section.

## Responsibilities
- Pulls the contracts the assembly gives and hands each internal module only the interfaces it uses.

## Not here
- The routes and their policies (the package's module). What each internal module does (its own card).

## Offers
- `handlersOver` (the build context, the lockout policy) → every route's handler, by name.
- `policyOf` (the section) → the lockout policy `rate-limit` judges.

## Invariants
- Internal modules: `transactions` keeps transactions; `proof` holds a login (the gate) or a session (step-up) until a factor is proved; `enrollment` binds a new factor; `reset` is the operator's reset; `release` the user's, by `permits`; `recording` records a request's audit events. `transactions` takes its own contracts; `wiring` gives the others only what they use.

## Depends on
- `kernel` (the build context); `audit`, `login-gates`, `mfa`, `mfa-binding-proof`, `rate-limit`, `session`, `subject-revocation` (the contracts it hands on); the package's internal modules, section and store interfaces.
