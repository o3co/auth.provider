# client-metadata

Internal module of `authorize`: what it contributes to `clients` for its requests.

## Responsibilities
- Names the client metadata section `authorize` contributes: `redirect-uris`' section of a client's redirect URIs.

## Not here
- The rules of a redirect URI and the section's schema (`redirect-uris`). Contributing it (the package's module).

## Offers
- `clientMetadata`: `section`, the section the package's module contributes to `clients`' `metadataSections`.

## Invariants
- It holds values alone: nothing here is checked or run.

## Depends on
- `redirect-uris`
