# description

Internal module of `idp-oidc`: the issuer's description (its OpenID Provider metadata), read and checked.

## Responsibilities
- Reads the issuer's description with discovery, and holds it to the settings; without discovery, takes the endpoints as the operator gives them.

## Not here
- The settings' own checks, given endpoints' included (`settings.ts`). Reading UserInfo (`userinfo`), beyond the check of the endpoint a description names for it.
- What the endpoints are used for: the upstream (`upstream.ts`).

## Offers
- `describedBy` (the IdP's settings, how it reaches the upstream, the hosts) → the endpoints (authorization, token, key set, end of session and UserInfo where there are), and whether the description offers `iss`; or throws, refusing boot.

## Invariants
- The description must name the issuer.
- A description that names an endpoint (its end of session included) on another host, as `outbound` matches hosts, refuses boot.
- A description whose browsed endpoints (authorization, end of session) `outbound.refusals`' `browsedRefusal` does not take, or whose token endpoint or key set the destination policy refuses, refuses boot.
- A description's refusal, `outbound` refusing to fetch it included, is told at `issuer`, with its reason; one the policy gives names the endpoint and the policy's reason. A description answered other than `200`, or that cannot be read as one (no JSON object, not its shape), refuses boot at the IdP, in `federation`'s words, not under `issuer`.

## Depends on
- `outbound`, `outbound-policy`, `host-entries`, `upstream-client` (`answerOf`); `userinfo`, for the endpoint a description names for it.
