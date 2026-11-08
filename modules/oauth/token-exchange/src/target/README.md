# target

Internal module of `token-exchange`: the scope and the one audience an exchange issues for.

## Responsibilities
- Chooses the scope and the audience from the request, the subject token and the client's allowance, and checks `resource` against that audience.

## Not here
- Verifying the tokens, the actor chain, the ties and issuing: `token-exchange`.
- What a client is allowed: `client-allowance`. How a `resource` is read: `resource-indicators`.

## Offers
- `targetWith` (the issuer) → `targetOf` (the request, the subject token): the scope and the one audience, or the refusal.

## Invariants
- The scope lies within the subject token's scope and the client's allowance; left out, it is the subject token's, cut to the client's. Wider is `invalid_scope`. For a foreign token, there is no scope or audience of its own: the client's allowance decides them, by the same rules for `audience` and `resource`.
- The audience is one the subject token holds and the client is allowed; left out, the only such one. A `resource` must be an absolute URI without a fragment (by `resource-indicators`), and that audience. Otherwise `invalid_target`. It declares it takes its audience from the request, so no rule refuses its `resource` first.

## Depends on
- `client-allowance`, `grants` (the request and its refusal), `resource-indicators`; `token-exchange`'s contract (the subject token)
