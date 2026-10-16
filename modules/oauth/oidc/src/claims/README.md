# claims

Internal module of `oidc`: the claim table, and mapping a user's attributes through it.

## Responsibilities
- Holds the fixed claim table: which claims each scope releases, and the attribute (by `users`' name) and type each is read from.
- Maps attributes to claims through the table.

## Not here
- Where the attributes come from (`subject-attributes`, through `oidc`'s module). Which scopes a request holds (the caller).

## Offers
- `claimsOf` (attributes, scope words → the released claims, frozen)
- `tableScopes` (the table's scopes, in order)
- `tableClaims` (the table's claims, in order)

## Depends on
- `oidc`'s contract (the claim type), `users` (the attribute names)
