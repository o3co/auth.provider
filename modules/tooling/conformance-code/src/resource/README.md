# resource

Internal module of `conformance-code`: the scenes of resource indicators (RFC 8707) in the code flow.

## Responsibilities
- Checks a `resource` at authorization and at the code's exchange and a refresh: the audience it narrows to, the refusals (`invalid_target`), what comes first (logging in, consent), and that nothing is read where the feature is not composed.

## Depends on
- The package's scene builder and browser; `conformance` (the target); `conformance-oauth` (clients and the part's switch)
