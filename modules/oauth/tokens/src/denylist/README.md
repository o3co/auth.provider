# denylist

Internal module of `tokens`: the access tokens revoked before their end.

## Responsibilities
- Keeps a revoked token's id through `tokens`' store interface for revoked tokens, and tells whether an id is kept.

## Not here
- Reading a token, and which token a revocation names (`tokens`). The store interface and its needs (`tokens`' contract).

## Offers
- `denylistOver` (the store, or none when the configuration does not handle revocation; the clock) → whether revocation is handled; revoke (id, expiry → revoked / invalid when past the allowance / unsupported without a store); holds (id → whether kept; false without a store).
- The allowance past expiry, for `tokens`' own checks of a token being revoked.

## Invariants
- Answers revoked only when the write is confirmed. Revokes a token past its expiry while it is still within the allowance (a host with a slow clock still sees it as valid).
- When the store is unavailable, answers unavailable, never a negative verdict.

## Data
- Revoked tokens, by token id, kept for what is left of the token plus the allowance (relative, since the place judges it by its own clock). An id kept already is revoked already: the same token always ends at the same time. What the place must keep them through is stated as its needs (never evicted, survives a crash, does not come back on failover). Since this state only ever refuses, confirmed reads are not needed.

## Depends on
- `kernel` (the clock); `tokens`' contract and store interface
