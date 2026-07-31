# RFC 8707 resource → audience binding (Stage 2)

- Status: accepted
- Date: 2026-07-31
- Closes: #173 (Stage 2 of the RFC 8707 work started in #172)

## Context

RFC 8707 §2 requires that an access token's audience be the resource
indicator(s) the client requested, and that the AS respond `invalid_target`
when it cannot bind the token to them.

Stage 1 (#172) shipped opt-in plumbing only: `oauth.resourceIndicator.enabled`
gates a `resource` parameter that is forwarded to `GrantPolicyHook.evaluate`,
with fail-closed validation of what the policy returns. Nothing checked that
the token was actually minted for the requested resource. A policy that allowed
the request without narrowing the audience — or narrowed it to something else —
produced a token whose `aud` was `client.allowedAudiences[0]`, the issuer, or
the client id, with no error.

The `oauth-token-exchange` grant already implemented the missing enforcement
for its own grant type (IH-8, v0.5.3). Stage 2 generalises that to the three
remaining grants.

## Decisions

### D1 — Enforcement is a shared check applied after the audience is final

`unrepresentedResources(resources, audience)` (in
`packages/oauth/src/grants/_resourceIndicator.mts`) returns the requested
resources the audience does not represent. Each grant calls it once, *after*
its audience is fully derived, and returns `400 invalid_target` when the result
is non-empty.

Placing it after derivation rather than inside the policy block is what makes
it total: it covers policy narrowing, the `allowedAudiences` fallback, the
issuer fallback, and the client-id default identically. An enforcement that
lived inside the policy branch would only ever check the case that was already
least likely to be wrong.

### D1b — When no policy narrows an audience, derive it from the request

RFC 8707 §2 asks the AS to bind the token to the requested resource, not
merely to check whether its default happens to match. So when `resource` is
present and the policy returned no `grantedAudience` — including when no policy
is wired at all — the audience is **derived** from the request:
`deriveAudienceFromResources` returns the single requested resource, and the
grant mints for it.

Enforcement alone was not enough, and shipping only that was a genuine defect:
it made every request whose resource differed from the grant's default audience
(`allowedAudiences[0]`, the issuer, the client id) fail, so RFC 8707 became
unusable unless a policy hook was wired — contradicting D3 below, which exists
precisely so the flag does not require one.

Derivation is bounded by `allowedAudiences ∪ {clientId}`, the same ceiling a
policy-returned audience is validated against (and the bound
`oauth-token-exchange` already uses). Without it, naming a resource would be
enough to mint a token for any audience — the opposite of what resource
indicators are for. A resource outside that set is not derivable, and the
enforcement in D1 then rejects it.

A policy-returned audience always wins; derivation only fills the gap the
policy left.

### D2 — Multiple distinct resources are rejected, not split or merged

#173 left this open ("the AS may issue one token per resource OR a single token
with the array as `aud` — design decision needed"). It is already decided by
the token shape: `generateToken` emits a single `aud` string. Two distinct
resources cannot both be represented, so the request is refused.

Rejecting is also what `oauth-token-exchange` already does, so the alternative
would have made two grants disagree about the same request. Issuing multiple
tokens was not considered further: it changes the token-endpoint response
shape, which is a far larger change than RFC 8707 support and is not required
by §2.

Repeated occurrences of the *same* resource are accepted — the client named one
target twice, which is not a widening.

### D3 — Enforcement is gated on the flag alone, not on a policy being wired

Stage 1 read `resource` only when `grantPolicy` was present, because forwarding
was all it did. Enforcement cannot inherit that condition: a deployment that
turns the flag on without a policy still derives an audience, and issuing that
token in response to a mismatched `resource` request is precisely the §2
violation. So Stage 2 reads `resource` whenever the flag is on.

With the flag off — the default — nothing changes.

### D4 — `authorization_code` evaluates at `/authorize`, enforces at `/token`

This is the decision #173 called non-trivial, because of the C-2 / D-1
invariant: the authorization code's scope and audience are decided once at
`/authorize` and persisted on the code, and the token endpoint must not
re-evaluate policy.

RFC 8707 permits `resource` at both endpoints for this flow, so both must be
handled.

**At `/authorize`:** `resource` is forwarded to `grantPolicy.evaluate`, letting
the policy narrow `grantedAudience` before it is persisted on the code. This is
the only place a policy may decide the audience, so the invariant is preserved
by construction. `/authorize` then applies the same representation check and
redirects `invalid_target` if the request cannot be satisfied.

**At `/token`:** if `resource` is present, it is compared against the audience
already persisted on the code. No policy invocation. The check is a pure
comparison, so it does not re-decide anything — it only refuses to return a
token that misrepresents what the client asked for.

The two options #173 sketched were both rejected as stated:

- *(a) as written* — "move the resource indicator to `/authorize` […] token
  endpoint just reads the persisted audience" — leaves a conformant client's
  `resource` at `/token` silently ignored, handing back a token whose `aud` is
  not what it asked for. Adopted for the `/authorize` half; the `/token` half
  needed the enforcement above.
- *(b)* — "permit token-endpoint policy invocation but ONLY for audience
  narrowing" — reintroduces the token-endpoint policy surface D-1 removed. A
  narrowing invocation is still an invocation, and the invariant is about where
  decisions are made, not about which field they touch.

### D5 — `/authorize` rejects rather than issuing a doomed code

A code whose persisted audience cannot represent the requested resource will
always fail at `/token`. Deferring the error there means the user completes an
interactive redirect before the client learns the request was impossible.
Rejecting at `/authorize` reports it while the client can still act, which is
where RFC 8707 §2 places the error for that endpoint.

### D6 — Warning, not silence, when a resource request meets no audience

A token with no audience represents nothing, so any `resource` request against
it is unsatisfiable and rejects. This matters for `authorization_code`, where a
code carrying no `grantedAudience` falls back to the client id: the fallback is
a real audience and is checked like any other, rather than being treated as
"unconstrained".

## Consequences

- Deployments running with `oauth.resourceIndicator.enabled = true` and a
  policy that does not narrow the audience will start seeing `invalid_target`
  where tokens were previously issued. That is the intended correction; the
  flag was documented as staged plumbing and this is the stage it was staged
  for.
- The check is one function used by four call sites (three grants plus
  `/authorize`), so the definition of "represented" cannot drift between them.
  `oauth-token-exchange` keeps its own IH-8 implementation, which predates this
  and is scoped to its own token-shape rules.
- Stage 3 ("`resource` MUST be present") remains out of scope and is a separate
  toggle, unchanged by this decision.

## References

- RFC 8707 §2 (resource indicators), RFC 6749 §5.2 (`invalid_target`)
- Stage 1: PR #172; enforcement reference: `packages/oauth-token-exchange/src/grant.mts`
- C-2 / D-1 invariant: `packages/oauth/src/grants/authorization.mts`
