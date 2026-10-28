# clients-cimd

## Responsibilities
- Contributes a client source to `clients`: for a client id that is a URL, fetches the metadata document there through `outbound`, judges it, and gives a public client.
- Says in the authorization server metadata that it takes such ids.
- Its internal modules: `document` reads and judges a document, `fetching` bounds the fetches and keeps their answers. The package's module only declares.

## Not here
- Authenticating by `none` (`clients`). Matching redirect URIs (`redirect-uris`). Consent and its page (`consent`). The destination policy (`outbound`).
- What each section takes from a document and what its values mean: each owner's copy, as `client-documents`' `documentCopies` holds them, and schema, as `metadataSections` holds them; `clients` refuses the record as a whole on any error.

## Offers
- Composition definition only: a contribution to `clientSources`, and the metadata item `client_id_metadata_document_supported` (`true`).
- Operator section: `allow` and `deny` (host names, read as `outbound` reads a list entry; `.name` also takes the names under it), `allow-any-host` (default false), `scopes` and `audiences` (the ceiling; default empty), `max-size` (default `5KiB`), `timeout` (default `5s`), `cache-lifetime` (default `10m`), `cache-entries` (default 256), `refused-lifetime` (default `1m`), `max-concurrent` (default 8). Times and sizes are written with a unit.

## Invariants
- Whether the code grant is composed is `grants`' `composedGrants`. Without it composed, nothing is fetched and the metadata item is left out; boot is not refused.
- An id is fetched only when it is https, has a path other than `/`, has no query, fragment, user information, IP literal, empty label or loopback host (`url-setting`'s `isLoopbackName`), and is written exactly as the URL parser writes it.
- Its host is checked before the fetch, spelled as `outbound` spells hosts: `deny` first, then `allow` unless `allow-any-host` is set. An `allow` list also narrows `outbound`'s hosts.
- Boot is refused at `allow` where it is empty and `allow-any-host` is not set: the operator names the document hosts, or takes any.
- `allow-any-host` takes any host `deny` leaves; every start logs the warning `clients-cimd.any_host_allowed`. Set beside a non-empty `allow`, it refuses boot at its key.
- The fetch goes only through `outbound`, asks for JSON, and narrows its size and time; it marks its destination `outsideChosen`, as an outside party chooses it, for outbound to keep its name lookups to their share. Only a `200` with a JSON media type and one object is a document.
- Boot is refused where `max-size` or `timeout` is above `outbound`'s cap, as its `outboundLimits` answers it, naming the key and no value, and where outbound gives the document's names no lookup (`lookupsOf`).
- Boot is refused where no composed copy reads `redirect_uris` or `client_name` (its `reads`), where a copy's section is not composed, and where a section it computes (`client-allowance`) is copied from a document too.
- The document's `client_id` equals the id. It has no `client_secret` or `client_secret_expires_at`, and its `token_endpoint_auth_method` is `none` or absent.
- `redirect_uris` is a non-empty list of strings, CIMD's rule for a client with the code flow alone: its section takes an empty list, and checks each URI's form. `grant_types` (default the code) holds the code; `response_types`, if present, holds `code`.
- Its allowances come from `client-allowance` within the ceiling: the code, refresh only when the document names it, the scopes it asks (all the ceiling's when it asks none), the operator's audiences. An empty answer refuses the record.
- Each other section is as its owner copies it from the document, with the id and its host; a field a copy refuses refuses the document. The client is public, by `none`, and never registered.
- A failed fetch or a refused document is no client (not unavailable). Other fields (keys, logo) are not read.
- A document whose record `clients`' `checkRecord` refuses (a redirect URI `redirect-uris` refuses, say) is refused before it is kept, logged with where the record fails (`record at sections.authorize.redirect-uris.0`), never a value; a check that throws is a failed fetch.
- A refused document, destination or outbound failure is remembered for `refused-lifetime`; running out of time or of `outbound`'s places is not.
- Fetches have no limit per time or per host beyond `max-concurrent`. Operators keep outside hosts from blocking them by narrowing the document hosts in `outbound`'s `allow`.
- Without that, a host that does not answer can fill the `max-concurrent` places (8 by default), and an id not kept is none meanwhile.
- A refused document's log line carries the id without control characters, cut to 200 characters, and the reason.
- A refused host's log line carries only the id's host and the reason (`denied` or `not allowed`).

## Data
- Kept documents, remembered refusals and running fetches, in this process only (see `fetching`). Safe on multiple instances.

## Depends on
- `kernel`, `clients`, `client-documents`, `client-allowance`, `outbound`, `outbound-policy`, `grants`, `code-grant`, `refresh`, `issuer`, `url-setting` (`isLoopbackName`)
