# token-denylist

## Responsibilities
- Owns the access tokens revoked before their end: keeps a revoked token's id, and tells whether an id is kept.
- Owns the store interface for revoked tokens, and the needs any implementation meets.

## Not here
- Reading a token, and which token a revocation names: `tokens`'. Where the ids are kept: a store wiring's.

## Offers
- `revokedTokens`, the store interface (id, lifetime → created / exists; id → kept), with its needs `revokedTokensNeeds`: never evicted, survives a crash, does not come back on failover. A wiring provides it.
- `denylistOver` (the store, or none when the configuration does not handle revocation; the clock) → whether revocation is handled; revoke (id, expiry → revoked / invalid when past the allowance / unsupported without a store); holds (id → whether kept; false without a store).
- `denylistAllowanceMs`: how long past its expiry a token is still revoked and held, 60 s.
- `./testing`: the store interface's contract test, every implementation's.

## Invariants
- Answers revoked only when the write is confirmed. Revokes a token past its expiry while it is still within the allowance (a host with a slow clock still sees it as valid).
- When the store is unavailable, answers unavailable, never a negative verdict.

## Data
- Revoked tokens, by token id, kept for what is left of the token plus the allowance (relative, since the place judges it by its own clock). An id kept already is revoked already: the same token always ends at the same time. Since this state only ever refuses, confirmed reads are not needed.

## Depends on
- `kernel` (the clock, the contract)

## Vocabulary
- allowance: how long past its expiry a revoked token stays held, so clocks apart never let it back early.
