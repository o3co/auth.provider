# held

Internal module of `upstream-handoff`: the logins a gate held, kept sealed until taken.

## Responsibilities
- Keeps a held login's upstream tokens sealed under its carry, and gives them back once.

## Not here
- When a login is held, who is told its tokens, and how long they live once handed: the package's `handoff`. Where records are kept: the held login store.

## Offers
- `heldOver` (the seal, the held login store) → `keep` (carry, held login, lifetime) and `take` (carry, subject, what uses the login).

## Invariants
- A held login is sealed with its IdP, local subject, hold time and tokens, bound to its carry, and kept for the lifetime given; if it cannot be kept, that is unavailable.
- It is taken once, in one rewrite, then removed after its use, which runs even where that use fails.
- It is handed only as a login of the subject asked; any other is handed as none.

## Data
- Held login record, by its carry: format 1, the sealed IdP, subject, hold time and tokens, and whether it was taken. One of another shape is none. The store derives its name from the carry, never keeps it in clear, and must never bring a taken one back on failover.

## Depends on
- `kernel`, `seal` (the seal's interface), `upstreams` (the tokens); the held login store
