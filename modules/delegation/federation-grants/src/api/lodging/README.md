# lodging

Internal module of `api`: a grant lodged, and a grant renewed.

## Responsibilities
- Lodges a pending grant with its first intent, and renews a grant with a new one: each read from the body, counted against the client's lodgings, written, and answered with the link a browser opens to connect.

## Not here
- Who owns a grant, its boundary and end: `routing`. The browser half: `intents`. The route's body: `body.ts`.

## Offers
- `lodgingWith` (the api's common parts) → `lodge`, `reauthorize`.

## Invariants
- An intent's return URI is one the client lists; its scopes lie within the connection's, `openid` among them, and `offline_access` where the connection asks it.
- Lodgings and renewals are counted together per client, whatever subject they name; past the pair's cap, the intents that end first are pushed out, and end.

## Depends on
- `clients`, `http`; `grant`, `body.ts`, the api's common parts.
