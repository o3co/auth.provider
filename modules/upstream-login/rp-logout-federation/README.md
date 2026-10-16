# rp-logout-federation

## Responsibilities
- Sends a logout a client starts on to the upstream the session came from, bridging `rp-logout` and `federation-tokens`.

## Not here
- The logout and its order of answers: `rp-logout`. Which upstream a session came from, and its end of session: `federation-tokens`.

## Offers
- Contribution to `rp-logout`'s upstream ends: `federation-tokens`'s end of session of the session's first upstream, with the return and state. The return goes to the upstream as the client registered it, so the upstream IdP must have it registered too.
- Log `rp-logout-federation.end_failed` (the error's type) when `federation-tokens` cannot answer; the logout goes on without the upstream.

## Invariants
- Boot is refused where `federation-tokens` is not composed.

## Data
- None.

## Depends on
- `kernel`, `rp-logout`, `federation-tokens`
