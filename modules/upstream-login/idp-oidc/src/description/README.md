# description

Internal module of `idp-oidc`: the issuer's description (its OpenID Provider metadata), read and checked.

## Responsibilities
- Reads the issuer's description with discovery, and holds it to the settings; without discovery, takes the endpoints as the operator gives them.
- Where the description cannot be read at boot, reads it again when it is needed, until a read holds.

## Not here
- The settings' own checks, given endpoints' included (`settings.ts`). Reading UserInfo (`userinfo`), beyond the check of the endpoint a description names for it.
- What the endpoints are used for, and what is unavailable without them: the upstream (`upstream.ts`).

## Offers
- `describedBy` (the IdP's settings, how it reaches the upstream, the hosts, the clock, log and IdP's name) → the description read (its endpoints, and whether it offers `iss`), or one awaited: `now()` (the description, or none, a read begun where one may) and `when()` (the description, a read awaited where one may begin, else Unavailable); or throws, refusing boot.

## Invariants
- Cannot be read: `outbound` cannot fetch it (`OutboundUnavailable`, in outbound's own word), or the issuer answers 5xx or 429. The issuer's state, not the settings': boot goes on, warning `idp-oidc.description_unavailable` with the IdP and that word (`status-5xx`, `status-429` for an answer), no value.
- Does not hold, refusing boot as before: any other answer, as below. Waiting does not change it.
- The description must name the issuer.
- A description that names an endpoint (its end of session included) on another host, as `outbound` matches hosts, refuses boot.
- A description whose browsed endpoints (authorization, end of session) `outbound.refusals`' `browsedRefusal` does not take, or whose token endpoint or key set the destination policy refuses, refuses boot.
- A description's refusal, `outbound` refusing to fetch it included, is told at `issuer`, with its reason; one the policy gives names the endpoint and the policy's reason. A description answered other than `200`, 5xx or 429, or that cannot be read as one (no JSON object, not its shape), refuses boot at the IdP, in `federation`'s words, not under `issuer`.
- Awaited, it is read only when needed, never on a timer: one read at a time, shared by all awaiting it, each beginning a minute after the last began at the soonest (a fixed floor that spares the issuer), the boot's read the first. A read is checked as at boot; one that does not hold is never used. Once one holds, it is never read again.
- What answers at once (a start, an end of session) begins the read and is unavailable itself, so the first start after the issuer is back answers 503; what awaits (an exchange, a refresh) goes on with a read that holds.
- A line is logged only where the outcome changes: `idp-oidc.description_read` (info), `idp-oidc.description_mismatch` (error, with its reason, no value), `description_unavailable` again after one. No readiness probe reads it.

## Depends on
- `kernel` (`Unavailable`, the clock, the log), `outbound`, `outbound-policy`, `host-entries`, `upstream-client` (`answerOf`); `userinfo`, for the endpoint a description names for it.
