# idps

Internal module of `federation`: opening the configured IdPs at boot.

## Responsibilities
- Opens each configured IdP through its type, and gives the round trip what it needs of it.
- Finds every reason to refuse boot at once.

## Not here
- What a type checks of its settings and its upstream (the type). Refusing boot (the package's module, with the reasons found here).

## Offers
- `idpsIn`, `upstreamsIn` and `amrSourceIn`: from the build context, the opened IdPs (refusing boot with every reason), `upstreams` over them, and `login-gates`' amr source (what a federation login proves and what the IdPs' amr maps to).
- `openIdps` (the offered IdP types, the section's `idps`, `http`'s public origin and whether its cookies can be secure) → the opened IdPs by name, and the reasons to refuse boot.

## Invariants
- Each IdP's redirect URI is the public origin plus its own callback path.
- An IdP is refused when no module offers its type, when its type refuses its settings (one reason per issue), with no public origin, or when its upstream does not match its settings.
- An IdP whose upstream answers in a posted form is refused when cookies cannot be secure.
- An IdP's type sees only its own settings, without `type` and `upstream-amr`.

## Depends on
- `http` (the site); `kernel` (the build context, refusals); `upstreams` (the IdP types); `federation`'s section; `round-trip` (what an opened IdP is, the callback path, the opened IdPs' contract, what a login proves)
