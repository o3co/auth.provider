# allowed

Internal module of `token-endpoint`: whether every grant a registered client is allowed is served.

## Responsibilities
- Finds each grant a registered client is allowed that no composed module serves, so boot is refused rather than the grant going missing in silence.

## Not here
- Which grants are composed, and refusing boot (the package's module). What a client is allowed (`client-allowance`). Which module serves a grant type (`grants`' index).

## Offers
- `unservedGrants` (the registered clients, the grant types composed) → a refusal for each such grant.

## Invariants
- A refusal is at `clients.registered.<i>.sections.client-allowance.grants.<j>`, naming the module `grants`' `grantServers` gives, or "the module that serves it" for a type it does not list; never the client's id or the grant type.

## Depends on
- `client-allowance` (`grantsOf`), `clients` (the client), `grants` (`grantServers`), `kernel` (the refusal)
