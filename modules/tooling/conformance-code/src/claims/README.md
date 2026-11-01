# claims

Internal module of `conformance-code`: the scenes of the claims a request names beyond its scope.

## Responsibilities
- Checks a claim asked through `claims` beyond the scope: released for userinfo or the ID token as asked, never one whose scope the client is not allowed, and left out where a value it asks does not match, a scope's claim too.
- Checks that a `sub` value asked names the only user a code is issued for, and that the metadata says the claims parameter is taken.

## Depends on
- The package's scene builder and browser; `conformance` (the target); `conformance-oauth` (clients)
