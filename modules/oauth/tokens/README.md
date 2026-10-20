# tokens

## Responsibilities
- Owns the access token: its format, issuance, verification and revocation; stamps and checks `issuer`'s URL as `iss`.
- Revokes through `token-denylist`'s denylist, over the store interface it offers and `tokens` passes on.
- Applies `added-claims`' rules to the claims a grant adds, at `issue`, at `admits` and when a token is read back.

## Not here
- The procedures that lead to issuance, authenticating the requester, and other token kinds.
- Binding kinds and a holder's proof: `sender-binding`'s.

## Offers
- Issuance only through `issue`, policies first: `issue(request: grant, grant type, session, `continuing` (set by an issuing side whose grant the policies already let through); limits)` → issued, or refused by the first policy to refuse.
- The order policies are asked in: tokens' own rule first (an authentication time over 300 s ahead of the clock), then the issuance policies in name order, each asked the grant as its caller verified it; any answer but allowed refuses. All of them answer within `issuance-timeout` together: past it the issuance is unavailable, and the signal each policy is given aborts.
- `admits` makes the same judgment without issuing; a policy that cannot tell is unavailable. `issue` takes one frozen copy of the request and its limits before anything waits: every policy reads it and the issuing signs it, so neither a policy nor a caller changing its own objects meanwhile changes what is signed.
- What it issues for: a grant (subject, issued-to, audience, scope; optionally an actor chain, `amr`, an authentication time, `acr` and the `claims` it adds), an expiry cap, a binding, and a lifetime other than the section's (1–86400 s) → the token, its id, expiry, token type and the added claims' names.
- Verification → the id, the grant (its added claims frozen), the token type (Bearer, or the bound kind's) and the binding; the validity check `sender-binding` admits a request at a resource by.
- Issued-to, for the revoking side to check the owner: answered for revoked tokens and within the allowance past expiry too; never for authorization.
- Revocation, directly or by a reference to an issued token (its shape is `tokens`' own), within the allowance past expiry; or unsupported, which `revocable` tells.
- Extension points: issuance policies (request → allowed / refused with an audit reason and a client description); access conditions, and exactly one subject check (token id, subject, issue time → holds / revoked; unavailable when unknown); a revoked answer fails the token as revoked. A policy reads session-built state late (`c.late`), else boot cycles.
- `token-denylist`'s store interface for revoked tokens and its needs, passed on: a store wiring wires `tokens` and implements it.
- `jwks_uri` among `issuer`'s metadata: `keys`' key set path on `http`'s public origin; left out without one.
- Operator section: `access-token-lifetime` (written with its unit, `1s` to `1d` in whole seconds, default `1h`), `revocation` (`denylist` or `unsupported`), `issuance-timeout` (written with its unit, `1s` to `1m`, default `10s`), `subject-check` (`none` states that no module checks subjects).
- `./testing`: the contract test every implementation passes, configuration builders, and a stand-in: in memory, unsigned, ending and reading bindings as `tokens` does.

## Invariants
- A token without `typ`, with several bindings, or with a binding no kind of the composition writes is refused.
- Signed and verified through `keys`' `accessTokenSigning` alone. A token whose `exp` comes before its `iat`, whose `iat` is over 60 s ahead of the clock (hosts' clocks differ), or with over a day between them is none `tokens` issues: refused as `shape`.
- `act`, `amr`, `auth_time` (to the second) and `acr` are written only when the grant gives them; an empty `amr` counts as none, `auth_time` is never after `iat`, and none is written where the grant marks its authentication time unknown; an empty `acr` or an authentication time that is no number is the caller's mistake.
- With no subject check, the section states `subject-check` `none`; with one, it does not; boot is refused otherwise. Under `none`, a revoked subject's boundary stops no access token: one lives until its expiry unless revoked another way, such as closing its session.
- Unavailable keys, store or checks answer unavailable, never a negative verdict.
- Added claims are the grant's statement: signed with the rest, a resource cannot tell them from the provider's, so composing a grant trusts it with its tokens' content.
- An added claim follows `added-claims`' rules, its shape, reserved names and limits; one outside them is the grant's maker's mistake (TypeError at `issue` and `admits`, a 500 with no audit), and a token read back with one is refused as `shape`.
- A token over 16 KiB, or an actor chain over 16, is neither issued (TypeError) nor read.

## Depends on
- `kernel`, `http`, `keys`, `issuer`, `sender-binding`, `added-claims`, `token-denylist`

## Vocabulary
- scope / audience: the range of permission a token grants, and the token's recipient.
- issued-to: the identifier of whoever received the token; its contents are not interpreted.
- actor: who acts for the subject, as a chain (`act`).
