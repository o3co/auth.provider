# grants

## Responsibilities
- Owns the grant extension point: what a grant is given, and how its answer is answered.
- Owns the rule for the audience a request asks for, as resource indicators (RFC 8707) contribute it.
- Defines the contract for the grant types composed (`composedGrants`).

## Not here
- Each grant's own decisions (the contributing side owns them). The token format (`tokens`).
- The token endpoint, its checks before a grant runs, and its audit (`token-endpoint`, which keeps this contract).

## Offers
- Extension point `grants`: grant type → handler, one for each grant type (two refuse boot).
- A grant runs only for an authenticated client it is allowed to, once the request's binding is read.
- A grant names the bodies it takes (a form when it names none). It reads a parameter as one string, or as sent (a JSON member of any type); a repeated parameter, or an OAuth parameter sent in JSON as neither a string nor `null`, never reaches it.
- A grant's refusal is an OAuth error code (`OAuthError`) or one the grant owns, answered `400`, or `401` for `invalid_client` or when the grant names it; any other status is ignored.
- A grant's `401` carries the `WWW-Authenticate` challenge of the client's authentication method, or every method's when it declares none; a grant sets no header.
- Other members of a grant's refusal pass through unread, but a member named as in the error or a success answer is dropped, and so is an `error_uri` that is not a URI of printable characters.
- A grant is given the request sender's binding.
- `admits`: whether `tokens`' issuance policies allow a grant now, under the grant type, the session it comes from and `tokens`' `continuing`.
- `issue`: asks again, then issues with the binding, and the expiry cap and lifetime the grant gives.
- A refused issuance is a value the grant returns unread; it is answered for every grant as `400 invalid_grant` with the policy's description.
- `target`: the audience `targets` answers within the grant's ceiling.
- A grant that takes its audience from the request declares `targets`; any other is first asked the rule's `untargeted`, and its refusal is answered before the grant runs.
- Extension point `sessionIssuances`: told the session and the token's id and expiry by `issue` given a session. One failing revokes the token, and `issue` throws it on.
- Extension point `targetRules`: at most one rule; two refuse boot.
- A rule's `target` is given the request's parameters, the default audience and whether the issuance may have another; it answers the audience, or `invalid_target` with a description, which is the answer.
- A rule may answer `untargeted` (the request's parameters, for a grant or endpoint that takes no audience) and `repeated` (a parameter's name, sent more than once) with `invalid_target`, which is then the answer.
- `targets`: the composed rule, provided by `token-endpoint`. With none composed, the default audience, the request unread.
- `composedGrants`: the grant types composed, answered by `token-endpoint`'s module.

## Depends on
- `kernel`, `http`, `clients`, `sender-binding`, `tokens`; kept by `token-endpoint`.

## Vocabulary
- grant: a procedure that issues tokens, chosen by grant type name.
