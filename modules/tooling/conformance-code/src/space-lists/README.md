# space-lists

Internal module of `conformance-code`: the scenes of the space-delimited lists the code flow writes and reads.

## Responsibilities
- Checks that the scope the token endpoint answers and the access token carries is written with one ASCII space between its values, and that a scope or prompt the authorization endpoint reads is split on that space alone.

## Depends on
- The package's scene builder and test tools; `conformance` (the target)
