# documents

Internal module of `conformance-code`: the scenes of clients whose id is the URL of their metadata document.

## Responsibilities
- Checks the ids refused before any fetch, the metadata saying such ids are taken, and a registered client whose id is a URL taken as registered, its document never fetched.
- Checks that a document is fetched from an allowed host while a logout's back channel limits outbound too, through a proxy that records each destination asked of it.
- Checks what a consent holds for: the destinations the consent page names for a client of either kind; that a client whose document changes in any field is asked again, with no code and nothing agreed to before carried over, a silent request refused, a challenge from before unknown and a claim's name cut; that a document back unchanged is asked nothing; and that a registered client's consent holds. Through a tunnel to a host the app reaches by name, whose documents the scene changes.
- Checks that a document whose https redirect URI is not followed by `//` is refused.

## Depends on
- The package's scene builder and browser; `conformance` (the target, its fake party and an area of the scene's own for the proxy); `conformance-legacy` (that area's set-up there, which cannot take a proxy); `conformance-front` and `conformance-tunnel` (the documents' host over https)
