# gate

Internal module of `login-passkey`: the gate `credential-policy`.

## Responsibilities
- Refuses a password login of a subject holding a passkey, where `password = refused-when-held`.

## Not here
- Running the gates, and what a refusal answers (`login-gates`, and the login's caller).

## Offers
- `gateIn` → the gate `credential-policy`, asked again on resume (`rechecked`).

## Invariants
- It passes every login unless `password = refused-when-held`, and every login whose amr has no `pwd`, or whose groups include `password-exempt-group`.
- Whether the subject holds a passkey is settled with the witness (`passkeyHolders.held`): a store that lost them is unavailable, never a pass.
- A refusal records `passkey.password_refused` with the subject and source.
- With `password = refused-when-held` and no passkey witness composed (`passkeyHolders.witnessed`), boot is refused: a lost store would read as holding none and let a former holder's password in.

## Depends on
- `login-gates`, `passkeys` (`passkeyHolders`); the internal module `audited`
