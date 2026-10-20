# upstream-round-trip

## Responsibilities
- Keeps one authorization round trip to an upstream, from its start to its callback, so a callback takes it once.
- Makes the round trip's secrets and the cookie that ties it to the browser.

## Not here
- The routes, their parameters (repeated ones, `error`, the code), and what is asked before a start: each caller's.
- The code exchange, and its issuer, nonce and token checks: the upstream's (`upstreams`' types).
- What follows a taken round trip (a login, a link, a grant's activation), and its session checks: each caller's.

## Offers
- `roundTrips.begin` (a name, what the caller carries as JSON, a lifetime, cross-site or not) → the state, nonce and S256 challenge for the upstream, and the cookie to set.
- `roundTrips.take` (the callback's request, the name, its `state`) → `taken` (what was carried, the verifier and nonce for the exchange, when it started, and the cookie cleared) or `none`.
- Composition definition (`./module`): provides `roundTrips` over the store interface the assembly wires and `cookies`.
- Store interface for round trips, its needs (survives failover, names from the secret) and contract test (`./testing`).
- The caller adds the cookie cleared to every answer after a take, and reads what it carried with its own schema.

## Invariants
- The cookie, state, nonce and verifier are 256 random bits each; the challenge is the verifier's S256.
- A round trip is kept under its cookie for the caller's lifetime; the cookie lives that long in whole seconds, rounded up, at least one.
- A record already under a fresh cookie is unavailable.
- The cookie is named by the caller's name; a cross-site one is set and cleared as such (`cookies`).
- A take reads the cookie through `cookies.lookup`: one absent or withheld takes nothing.
- In one change of the record: only the name's own record, its state compared in constant time, is marked taken; its lifetime is kept.
- A take counts only when the record read was untaken and the one written is taken, so one of two callbacks at once takes it.
- Nothing taken spends nothing and clears no cookie; a taken one is never taken again.
- Two round trips of one name begun in one browser leave only the later one takeable.

## Data
- Round trip record, by its cookie: format 1, the name, state, nonce, verifier, start time, what was carried, whether cross-site, and whether taken. The store derives its name from the cookie and never keeps the cookie in clear.

## Depends on
- `kernel`, `cookies`, `http` (the request type)

## Vocabulary
- round trip: one authorization request to an upstream and its callback, taken once.
