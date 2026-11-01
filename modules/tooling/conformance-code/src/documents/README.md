# documents

Internal module of `conformance-code`: the scenes of clients whose id is the URL of their metadata document.

## Responsibilities
- Checks the ids refused before any fetch, the metadata saying such ids are taken, and a registered client whose id is a URL taken as registered, its document never fetched.
- Checks that a document is fetched from an allowed host while a logout's back channel limits outbound too, through a proxy that records each destination asked of it.

## Depends on
- The package's scene builder and browser; `conformance` (the target, its fake party and an area of the scene's own for the proxy); `conformance-legacy` (that area's set-up there, which cannot take a proxy)
