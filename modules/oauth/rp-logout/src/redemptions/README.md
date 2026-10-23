# redemptions

Internal module of `rp-logout`: which clients redeemed a code in each session, kept so that the session's close can tell them.

## Responsibilities
- Keeps each client `code-grant` tells of, for the session it redeemed a code in, in the store of the clients of each session.

## Not here
- The store itself (the package's store interface, wired by the assembly). Telling the clients a session closed (`notices`, `page`).

## Offers
- `remembering` (the module's parts, the package's name) → the contribution to `code-grant`'s session redemptions.

## Invariants
- A client is kept until the session ends, and at least `remember-for`; for a session whose end is unknown, `remember-for` alone.
- A client the store pushes out of a session's set is logged, as `rp-logout.clients_pushed_out` with how many.

## Depends on
- `code-grant` (session redemptions); `session` (the session's end, asked late: session's own build asks the participants); `kernel` (the module's parts); the package's section and store interface.
