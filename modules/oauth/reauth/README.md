# reauth

## Responsibilities
- Owns re-authentication requests: records asked for one authorization request, taken once, kept through the store the assembly wires.
- Decides whether a login is fresh enough for `prompt=login`, `max_age` and an essential `auth_time`.

## Not here
- When a record is asked for and what is answered without one (`authorize`). The table of authentication levels (`acr`).

## Offers
- Contract `reauths`:
  - `remember` (the request's parameters, the time a login counts from, whether it is the step-up round trip → the record's name).
  - `take` (name, the request's parameters → the record, or none).
  - `fresh` (`prompt=login` asked, `max_age` in ms, whether a known authentication time is needed; the session's authentication time or that it is unknown; the taken record → yes / no).
- Store interface (the assembly wires the implementation): re-authentications (per name, an unguessable value the place never keeps in clear; save / update from the current contents). Record contents are not shown to the store. Needs (`reauthStoreNeeds`): survives a crash, never rolled back by failover, names that derive from the unguessable value.
- `./testing`: the contract test of the store interface, for every implementation.

## Invariants
- A record lives 10 minutes. A new record's name is made from 32 random bytes; if the name is already held, unavailable.
- The request's hash covers its parameters (each one's first value) except the record's own name, independent of their order and of the order of prompt words.
- Taking rewrites the record as taken; it counts only when that rewrite found it untaken and made for the same request. A name that is not 43 base64url characters is not looked up.
- A login whose authentication time `session` answers as unknown is never fresh: it meets no record, no `max_age` and no need for a known time.
- A login meets a record when its authentication time is the record's moment or later, compared to the millisecond. `max_age` is compared on `kernel`'s clock.

## Data
- Re-authentication record, per name, through the store interface, written in format 1: the time a login counts from, a hash of the request, whether it is the step-up round trip, and whether it was taken. Checked on every read; one of another format or shape reads as none, and eviction only means logging in again.

## Depends on
- `kernel` (the clock, randomness, unavailable), `session` (the authentication context), `zod`.

## Vocabulary
- Re-authentication request: a record, arising from `prompt=login`, `max_age` or an essential `auth_time`, that asks for the next authentication.
