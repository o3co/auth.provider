# names

Internal module of `conformance-federation`: the fault scenes of an IdP name's issuer across starts, each start a deployment of its own on one Redis.

## Responsibilities
- Checks that a name standing for another issuer than at an earlier start refuses boot telling no issuer, with a ledger holding the links too, and for a linked JWT bearer issuer's upstream, while an unchanged one boots with no warning.
- Checks that a new name does not reach an old name's link, that a stated move is taken and warned of, and that a move that does not match refuses boot.
- Checks that a GitHub Enterprise's API pointed elsewhere under a name, its `issuer` left out, refuses boot unless the move is stated, the link going with the name, and that a name a linked JWT bearer issuer also declares is refused unless it declares that same API.
- Checks that a grant's refresh reaches no other issuer than the one it was connected at.

## Depends on
- `grants` (the grants' scene and steps), the package's scene builder, browser, fake upstream and fake GitHub; `conformance` (the deployment and the topology); `conformance-identity`, `conformance-keys`, `conformance-oauth` (the parts of a linked issuer's scene)
