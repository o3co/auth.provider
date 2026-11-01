# discovery

Internal module of `conformance-code`: the scene of the whole metadata document of an OpenID Provider.

## Responsibilities
- Checks that the document a code flow deployment serves is one JSON object of OpenID Connect Discovery's form: the members it requires, each value of its type, and no value without one.

## Depends on
- The package's scene builder; `conformance` (the target)
