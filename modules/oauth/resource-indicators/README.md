# resource-indicators

## Responsibilities
- Contributes the rule for the audience a request asks for (RFC 8707) to `grants`' target rules: reads the `resource` parameter and narrows the audience issued to it, or refuses it where the grant takes no audience.

## Not here
- The audiences an issuance may have, and its default: each caller's (`client-allowance`'s, `code-grant`'s code, `refresh`'s family).
- Where the rule is asked and how its refusal is answered: `authorize` and the grants, through `token-endpoint`.
- The `resource` and `audience` of token exchange: `token-exchange`'s, composed or not, which reads a `resource`'s form by `resourceRefusal`.
- Any other repeated parameter: refused before the rule is asked.
- Which grants take an audience: each grant's, declared to `token-endpoint`.

## Offers
- Composition definition: a contribution to `targetRules`. No operator section; composing it turns it on.
- `resourceRefusal` (root): why a `resource` is not one to take (not an absolute URI, or carrying a fragment, RFC 8707 §2), none for one to take; its form alone, for any caller.

## Invariants
- No `resource`, or an empty one, keeps the default audience.
- A `resource` that is not an absolute URI (a scheme, printable ASCII alone as RFC 3986 writes one, one `URL` parses), or that carries a fragment, is refused `invalid_target`, whatever audience is registered.
- A `resource` the issuance may have is the audience, alone; it is compared as a string, as written.
- Any other is refused `invalid_target`, described by a fixed text that does not echo the value.
- A `resource` sent to a grant that takes no audience, or to another endpoint that asks, is refused `invalid_target` with a fixed text; none, or an empty one, is not.
- `resource` sent more than once is refused `invalid_target`: one audience is ever issued.
- Narrows only: the audience is always one the caller allows. No failure: the rule is pure.
- Without it composed, `resource` is read nowhere and every answer stays as it was.

## Data
- None, so it is safe on many instances.

## Depends on
- `kernel`, `grants`
