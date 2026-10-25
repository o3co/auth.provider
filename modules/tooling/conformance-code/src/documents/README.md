# documents

Internal module of `conformance-code`: the scenes of clients whose id is the URL of their metadata document.

## Responsibilities
- Checks the ids refused before any fetch, the metadata saying such ids are taken, and a registered client whose id is a URL taken as registered, its document never fetched.

## Depends on
- The package's scene builder and browser; `conformance` (the target and its fake party)
