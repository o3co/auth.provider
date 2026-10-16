# resource-indicators

## Responsibilities
- Contributes the rule for the audience a request asks for (RFC 8707) to `grants`' target rules: reads the `resource` parameter and narrows the audience issued to it, or refuses it where the grant takes no audience.

## Not here
- The audiences an issuance may have, and its default: each caller's (`client-allowance`'s, `code-grant`'s code, `refresh`'s family).
- Where the rule is asked and how its refusal is answered: `authorize` and the grants, through `token-endpoint`.
- The `resource` and `audience` of token exchange: `token-exchange`'s, composed or not.
- Any other repeated parameter: refused before the rule is asked.
- Which grants take an audience: each grant's, declared to `token-endpoint`.

## Offers
- Composition definition only: a contribution to `targetRules`. No operator section; composing it turns it on.

## Invariants
- No `resource`, or an empty one, keeps the default audience.
- A `resource` the issuance may have is the audience, alone; it is compared as a string, its form unchecked.
- Any other is refused `invalid_target`, described by a fixed text that does not echo the value.
- A `resource` sent to a grant that takes no audience, or to another endpoint that asks, is refused `invalid_target` with a fixed text; none, or an empty one, is not.
- `resource` sent more than once is refused `invalid_target`: one audience is ever issued.
- Narrows only: the audience is always one the caller allows. No failure: the rule is pure.
- Without it composed, `resource` is read nowhere and every answer stays as it was.

## Data
- None, so it is safe on many instances.

## Depends on
- `kernel`, `grants`
