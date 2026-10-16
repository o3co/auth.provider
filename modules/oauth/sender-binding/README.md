# sender-binding

## Responsibilities
- Owns the sender binding of tokens: the extension point of binding kinds, reading which binding a request proves, and the shape of a binding a token carries.
- Admits a request presenting a token at a resource of this provider (RFC 6750, RFC 9449): the scheme against the token's type, the token's validity through its issuer, then the holder's binding.

## Not here
- How each kind proves possession: the contributing side, such as `dpop` or `mtls`. Stamping a binding into a token and checking its validity: `tokens`.
- When a binding is asked for, and how a client's requirement is answered: the issuing side. What a resource grants once admitted (scope, audience): the resource.

## Offers
- Extension point: binding kinds. A kind declares the `cnf` member it writes, the name operators give it (`dpop`), its token type and whether its proof is explicit (sent on purpose, as DPoP's), reads `http`'s frozen request, the scene (issuance or resource) and `issuer`'s URL, and answers bound, none, or refused (its own code, unavailable, or headers to add).
- Reading a request's binding: bound, none, refused, or `multiple_bindings`. Operator section `dispatch`: `intent-explicit` (default, as 0.17), where an explicit kind's binding wins over ambient ones and two of one tier are refused; or `strict-mutual-exclusion`, where any two are.
- The token type of the kind that writes a `cnf` member; none for a member no kind writes.
- Whether two bindings are the same: the same kind and key, or both absent.
- Carrying bindings to an issued token: the presented tokens' bindings and the proved one → carry (bound to the proved one, if any) or refused.
- Admission at a resource, over the issuer's validity check (which `tokens` implements) → admitted with the check's valid answer, or refused with a status and `WWW-Authenticate`:
  - no token in a known scheme, or a scheme with nothing after it: `401`, every scheme challenged, no error; a malformed `Authorization` (a token outside RFC 6750's b64token) or two bindings: `400` `invalid_request`;
  - a token not valid, presented in another scheme than its type, bound by a member no kind writes, or whose holder proves no binding or another: `401` `invalid_token`;
  - a kind's refusal: `401` with its code and headers, challenged in that kind's scheme; a kind's own challenge replaces it; unavailable is thrown.
- `challengeOf` (token type, error): a resource's own challenge for a token it refuses itself.
- Client metadata section `sender-binding`: `required` (default false) and `kinds`, by the names kinds give operators (unwritten: any); `clientBindings` answers a binding read at issuance with `required` when there is none, `kind` when its kind is not named. A registered client naming no kind, or one no composed kind has, refuses boot, as do two kinds of one name.
- Composition definition.

## Invariants
- Kinds are read one at a time in the order of their members, whatever the assembly's order. The first refusal answers at once, over any binding another kind found; later kinds are not read.
- At a resource, validity is checked before any binding is read, and an unbound token reads none, so no proof is spent on a token that is refused or needs none.
- A bound token presented in another scheme is refused, so a binding cannot be stripped.
- Carrying refuses unless each binding a presented token holds is the proved one, so no binding is washed off and two different ones are refused.
- One kind per `cnf` member; two contributions for one member refuse boot.
- A challenge carries no `realm`.

## Depends on
- `kernel`, `http`, `issuer`, `clients` (the section)

## Vocabulary
- binding: the OAuth sender binding of a token to the key its sender proves (`cnf`).
- confirmation: the key's value a binding holds in its `cnf` member.
- kind: one way of proving a binding, writing one `cnf` member.
