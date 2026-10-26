# userinfo

Internal module of `idp-oidc`: reading an upstream's UserInfo after a login, where the operator turns it on.

## Responsibilities
- Reads UserInfo for a login's tokens, and checks at boot that the description's UserInfo endpoint can be read from.

## Not here
- Taking the answer and completing the login's profile with it (`upstream-client`'s id_token reader). The settings' own checks (`settings.ts`).

## Offers
- Settings, under the IdP: `read-userinfo` (default false); `userinfo-endpoint`, required with it and without discovery, refused otherwise.
- `userinfoOf` (outbound, the endpoint, the login's tokens, the narrowing) → the answer. `describedUserinfoRefusal` (the description's endpoint, the hosts, the narrowing, outbound's refusals) → why it cannot be read from, or none.

## Invariants
- UserInfo is read only for a login's code, after its id_token holds; never for a refresh, nor for a delegation's code.
- It is a `GET`, the access token sent as the Bearer credential to that endpoint alone. A token that is no Bearer token refuses the login, UserInfo asked nothing.
- A 5xx, or UserInfo out of reach (outbound unavailable: no connection, TLS, time, size), is unavailable; any other answer `upstream-client` does not take refuses the login, none of its values used.
- With `read-userinfo`, UserInfo and the description it is read from are https, whatever `outbound` takes: the access token and unsigned profile claims never go over plain http. One given on http, or an issuer on http with discovery, refuses boot at its key.
- With discovery, a description naming no UserInfo, one on a host the operator did not name, one not on https, or one outbound's policy refuses, refuses boot at `issuer`. Without `read-userinfo`, a description's UserInfo is no matter.
