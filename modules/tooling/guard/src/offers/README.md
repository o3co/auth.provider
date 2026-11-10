# offers

Internal module of `guard`: whether a package's card lists what its entry points export.

## Responsibilities
- Reads, for each entry point a package's manifest names, the exports its card does not list.

## Not here
- What an entry exports and what each export's signature carries: `guard-imports`' `surfacesOf`.
- Whether a card's words name exports that exist: review judges.

## Offers
- `unlistedExports` (packages → each package and entry whose exports the card does not all list, with those names), and the two readings it is made of: `listedOn` (card → the names it lists) and `unlistedIn` (surface, listed names → the exports not listed).

## Invariants
- A card lists a name when its Offers or Deprecated section backticks it, alone or as the name a call, a type's arguments, a member or an index open with (`name(…)`, `Name<…>`, `name.member`). A name written without backticks is not listed.
- Every exported value is listed, but a `./module`'s default (the module itself). A type that an exported value's signature carries, or that a carried type carries in turn, belongs to that value and need not be listed; listing it is allowed. A contract's or extension point's interface is carried by its token.
- Every entry point counts: `.`, `./testing`, `./module` and `./audit-events`, as the manifest names them.

## Depends on
- `guard-imports`: `surfacesOf`, an entry's exports and what each carries.
