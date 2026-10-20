# grants

## Responsibilities
- Owns the grant extension point: what a grant is given, and how its answer is answered.
- Owns the rule for the audience a request asks for, contributed as resource indicators (RFC 8707).
- Defines the contract for the grant types composed (`composedGrants`).

## Not here
- Each grant's own decisions (its contributor's). The token format (`tokens`).
- The token endpoint, its checks before a grant runs and its audit (`token-endpoint`, keeping this contract).

## Offers
- Extension point `grants`: grant type → handler, one for each grant type (two refuse boot).
- A grant runs only for an authenticated client allowed it, once the request sender's binding is read, and is given it.
- A grant names the bodies it takes (a form by default). It reads a parameter as one string, or as sent (a JSON member of any type); a repeated parameter, or an OAuth one sent in JSON as neither a string nor `null`, never reaches it.
- A grant's refusal is an OAuth error code (`OAuthError`) or one the grant owns, answered `400`, or `401` for `invalid_client` or as the grant names; any other status is ignored.
- A grant's `401` carries the client's method's `WWW-Authenticate` challenge, or every method's when it declares none; a grant sets no header.
- Other members of a grant's refusal pass unread, but one named as an error's or a success answer's member is dropped, as is an `error_uri` not a URI of printable characters.
- `admits`: whether `tokens`' issuance policies allow a grant now, given its grant type, session and `tokens`' `continuing`.
- `issue`: asks again, then issues with the binding and the grant's expiry cap and lifetime.
- A refused issuance, returned by the grant unread, is answered for every grant as `400 invalid_grant` with the policy's description.
- `target`: the audience `targets` answers within the grant's ceiling.
- A grant that takes its audience from the request declares `targets`; any other is first asked the rule's `untargeted`, whose refusal is answered before the grant runs.
- A grant declares `readsAmbient`: `cookie` when it reads the session's cookie, which a browser sends by itself, and so checks the request's origin itself, else `none`; the token endpoint's route, with no own-site policy, relies on this declaration, never a proof.
- Extension point `sessionIssuances`: told by `issue` the session it is given and the token's id and expiry; one failing revokes the token, and `issue` throws it on.
- Extension point `tokenTies`, one per `name`, of a verified token issued here: `none`, `ended` (a `reason` read after its name: `family has ended`), or `held`, with an end, a session to issue from and `join` for a token issued from it.
- Extension point `targetRules`: at most one rule; two refuse boot.
- A rule's `target`, given the request's parameters, the default audience and whether another may be issued, answers the audience or `invalid_target` with a description as the answer.
- A rule may answer `untargeted` (the parameters of a request to a grant or endpoint taking no audience) and `repeated` (a parameter sent more than once) with `invalid_target`, then the answer.
- `targets`: the composed rule, from `token-endpoint`; with none, the default audience, the request unread.
- `composedGrants`: the grant types composed, answered by `token-endpoint`'s module.

## Depends on
- `kernel`, `http`, `clients`, `sender-binding`, `tokens`; kept by `token-endpoint`.

## Vocabulary
- grant: a procedure that issues tokens, chosen by grant type name.
- tie: a family or session a token ends with, kept by its owner.
