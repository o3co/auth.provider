# sender-binding

## Responsibilities
- Owns the sender binding of tokens: the extension point of binding kinds, reading which binding a request proves, and the shape of a binding a token carries.
- Admits a request presenting a token at a resource of this provider (RFC 6750, RFC 9449): the scheme against the token's type, the token's validity through its issuer, then the holder's binding.

## Not here
- How each kind proves possession: the contributing side, such as `dpop` or `mtls`. Stamping a binding into a token and checking its validity: `tokens`.
- When a binding is asked for, and how a client's requirement is answered: the issuing side. What a resource grants once admitted (scope, audience): the resource.

## Offers
- Extension point `senderBindings`: binding kinds. A kind declares the `cnf` member it writes, the name operators give it (`dpop`), its token type and whether its proof is explicit (sent on purpose, as DPoP's), reads `http`'s frozen request, the scene (issuance, or a resource with the token, the binding it holds and its subject) and `issuer`'s URL, and answers bound, none, or refused (its own code, unavailable, too many, or headers to add).
- Contract `senderBinding`, reading a request's binding (`bindingOf`): bound, none, refused, or `multiple_bindings`. Operator section `dispatch`: `intent-explicit` (default, as 0.17), where an explicit kind's binding wins over ambient ones and two of one tier are refused; or `strict-mutual-exclusion`, where any two are.
- `senderBinding.tokenTypeOf`: the token type of the kind that writes a `cnf` member; none for a member no kind writes.
- `sameBinding`: whether two bindings are the same: the same kind and key, or both absent.
- `carried`: carrying bindings to an issued token: the presented tokens' bindings and the proved one → carry (bound to the proved one, if any) or refused.
- Admission at a resource, over the issuer's validity check (which `tokens` implements, a valid answer naming the token's subject) → admitted with the check's valid answer, or refused with a status and `WWW-Authenticate`:
  - no token in a known scheme, or a scheme with nothing after it: `401`, every scheme challenged, no error; a malformed `Authorization` (a token outside RFC 6750's b64token) or two bindings: `400` `invalid_request`;
  - a token not valid, presented in another scheme than its type, bound by a member no kind writes, or whose holder proves no binding or another: `401` `invalid_token`;
  - a kind's refusal: `401` with its code and headers, challenged in that kind's scheme; a kind's own challenge replaces it; unavailable is thrown;
  - a kind's too many: `429` with its code and headers, a `retry-after` among them, and no challenge.
- `challengeOf` (token type, error): a resource's own challenge for a token it refuses itself.
- Client metadata section `sender-binding`: `required` (default false) and `kinds`, by the names kinds give operators (unwritten: any); `clientBindings` answers a binding read at issuance with `required` when there is none, `kind` when its kind is not named. A registered client naming no kind, or one no composed kind has, refuses boot, as do two kinds of one name.
- Composition definition.

## Invariants
- Kinds are read one at a time in the order of their members, whatever the assembly's order. The first refusal answers at once, over any binding another kind found; later kinds are not read.
- At a resource, validity is checked before any binding is read, and an unbound token reads none, so no proof is spent on a token that is refused or needs none. A kind is told the binding the token holds, so a proof that does not prove it need spend nothing, and the subject its issuer names, passed on unread.
- A bound token presented in another scheme is refused, so a binding cannot be stripped.
- Carrying refuses unless each binding a presented token holds is the proved one, so no binding is washed off and two different ones are refused.
- One kind per `cnf` member; two contributions for one member refuse boot.
- A challenge carries no `realm`.

## Depends on
- `kernel`, `http`, `issuer`, `clients` (the section)

## Vocabulary
- binding: the OAuth sender binding of a token to the key its sender proves (`cnf`).
- confirmation: the key's value a binding holds in its `cnf` member.
- subject: whom a token stands for, in `tokens`' meaning.
- kind: one way of proving a binding, writing one `cnf` member.
