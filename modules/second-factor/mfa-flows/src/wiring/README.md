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
- `gating` (the module's parts) → the gate `mfa` contributed to `login-gates`, over the factors and the transactions.
- What each helper takes from the build context (`gatingTakes`, `partsTakes`, `handlersTakes`, the transactions' included), which the module's takes gather.

## Invariants
- Internal modules: `transactions` keeps transactions; `proof` holds a login (the gate) or a session (step-up) until a factor is proved; `release` is the user's release of their lockout, by `permits`; `recording` records a request's audit events; `requests` reads what a request names and holds the answers routes share; `seams` shapes what the module binding factors gives and takes. `transactions` takes its own contracts; `wiring` gives the others only what they use.
- The enrollment routes and an enrollment's challenge go to the flow contributed to `enrollmentFlow`.

## Depends on
- `kernel` (the build context); `audit`, `login-gates`, `mfa-reading`, `rate-limit`, `session`, `subject-revocation` (the contracts it hands on); the package's contract (`enrollmentFlow`), internal modules, section and store interfaces.
