# ADR 2026-05-20 — Token binding is a first-class extension surface

## Status

Accepted (2026-05-20). Implements the Wave 2 Token-binding Cluster
(DPoP + mTLS + introspect cnf typing). The cluster spec lives in
the internal agent-scope workspace alongside other planning material
and is not shipped in the OSS repo; this ADR is the public summary
of the load-bearing decisions.

## Context

Prior to Wave 2, sender-constrained token binding existed only as an
ad-hoc DPoP integration:

- `tokenBindingMw` was a hand-rolled middleware that consulted a hard-
  coded DPoP verifier and stamped `req.tokenBinding`.
- The `cnf` claim was emitted from a single grant-side gate
  (`bindingIsDpop && isPublicClient`) hard-wired to DPoP semantics.
- Downstream packages that wanted to add a new binding mechanism
  (mTLS, FIDO attestation, BBS+, anything else) had no extension
  surface. They would have had to fork `@o3co/auth-provider-core`,
  edit the middleware, edit the grant gates, and edit the introspect
  response shape.

Three concrete forcing functions made this unsustainable:

1. **RFC 8705 mTLS** (Phase 3) needed a second mechanism with its own
   evidence shape (`x5t#S256` thumbprint) and its own validation
   pipeline (PEM ↔ DER ↔ X509 ↔ PKI chain). Bolting it onto the
   DPoP middleware would have produced an `if (kind === "dpop") ...
   else if (kind === "mtls") ...` switch that every downstream
   reviewer would have to re-audit.

2. **Cross-mechanism arbitration**: a request can present both a DPoP
   header and an mTLS client cert. Without a typed binding interface
   there is no single place to express "DPoP wins because the header
   is explicit-intent" or "reject both because the operator wants
   strict mutual exclusion".

3. **Compound `cnf` runtime defense** (Codex Critical #2): the
   TypeScript layer can narrow `Confirmation` to a union of single-
   arm shapes, but a JWT payload is decoded at runtime. A malformed
   signed RT carrying BOTH `cnf.jkt` AND `cnf.x5t#S256` must be
   rejected at the grant boundary, not silently honored by whichever
   matrix runs first.

The pre-Wave 2 surface could not express any of these structurally —
each would have required ad-hoc workarounds layered on top of an
already-DPoP-specific design.

## Decision

Token binding is now an extension surface in
`@o3co/auth-provider-core` with three load-bearing types and one
contribution slot.

### 1. `TokenBinding` (core)

```typescript
export interface TokenBinding {
    readonly kind: string;
    readonly confirmation: Confirmation;
}
```

The cross-cutting shape. `kind` is a string (not a fixed enum) so
downstream mechanisms can extend the union additively. `confirmation`
is the RFC 7800 cnf claim payload; its variants live in the
`Confirmation` union below.

### 2. `Confirmation` union (core)

```typescript
export type Confirmation =
    | { readonly jkt: string }
    | { readonly "x5t#S256": string };
```

Narrow single-arm union. RFC 7800 permits structured values
(e.g. `jwk`) but adding a new variant is a deliberate core
semver-minor change, not a downstream-only extension. The narrowness
is the load-bearing safety property: a malformed `{ jkt, x5t#S256 }`
cannot type-check at the TypeScript layer (the runtime compound-
`cnf` reject is the cross-layer defense).

### 3. `TokenBindingMechanism` (core)

```typescript
export interface TokenBindingMechanism {
    readonly kind: string;
    readonly intentExplicit: boolean;
    extract(req: Request): Promise<TokenBinding | null>;
}
```

The verb-side abstraction. A mechanism is anything that can look at a
request and produce a `TokenBinding`. `intentExplicit` is the
dispatch hint — `true` for DPoP (the client sent a header on
purpose), `false` for mTLS (the cert is ambient).

### 4. `tokenBindingMechanisms` contribution slot (core)

```typescript
export type TokenBindingMechanismFactory<Deps> =
    (deps: Deps) => TokenBindingMechanism | null;
```

A new entry in `ContributesMap` declared in `@o3co/auth-provider-core`.
Mechanism modules (`dpopModule`, `mtlsModule`, future) contribute
factories that return their `TokenBindingMechanism`. Core's
`assembleApp` collects all contributions, filters nulls, and composes
ONE `tokenBindingMw` mounted on `/oauth/token` BEFORE the existing
`grantMiddleware` loop. The configured `DispatchPolicy`
(`oauth.tokenBinding.dispatch-policy`, single source of truth in
core's `CoreConfigSchema`) arbitrates across mechanisms:

- `intent-explicit` (default) — prefer mechanisms with
  `intentExplicit: true`. Resolves "DPoP header + mTLS cert"
  collisions in DPoP's favor.
- `strict-mutual-exclusion` — reject with `invalid_request` if more
  than one mechanism's `extract` returns a non-null binding.

### 5. Grant-side allowlist (oauth)

The Phase 3 §9.1 / §9.2 gate widening uses an explicit allowlist, not
`confirmation !== undefined`:

```typescript
const bindRefreshToken =
    (bindingIsDpop || bindingIsMtls) && isPublicClient;
```

The structural reason: the `Confirmation` union is mechanism-
extensible, so a custom mechanism emitting `{ jkt: "..." }` or
`{ "x5t#S256": "..." }` could otherwise satisfy a DPoP-bound or
mTLS-bound RT without going through the right matrix. Restricting
each matrix to its declared mechanism (`kind === "dpop"` /
`kind === "mtls"`) enforces the boundary structurally. Adding a new
mechanism to the allowlist MUST land its refresh-time matrix in the
same PR so a bound RT can never be issued without enforcement.

## Consequences

### Good

- **Downstream extensibility.** A new mechanism is a new package that
  implements `TokenBindingMechanism` + ships a `Module` contributing
  to `tokenBindingMechanisms`. No edit to `@o3co/auth-provider-core`,
  no edit to `@o3co/auth-provider-oauth` grant code beyond the gate-
  allowlist entry (which the new package's own PR adds).
- **Cross-module arbitration is a single configurable policy** — not
  a fork-per-deployment ad-hoc resolution rule.
- **Compound-`cnf` runtime defense is mechanism-agnostic**, not
  duplicated per mechanism. It is applied per AS surface that acts on a
  `cnf`, using one shared shape check — see below.
- **Introspect cnf is mechanism-agnostic.** The introspect handler
  reads `cnf` from the AT claims and decides `token_type` based on
  whether `jkt` is present (DPoP → "DPoP" per RFC 9449 §5) or not
  (Bearer for mTLS + unbound per RFC 8705 §3). No mechanism-specific
  branches.

#### Compound cnf across the AS surfaces

Amended 2026-07-31 (resolves the audit finding #199 I3 / R4). The
original wording — "compound-`cnf` runtime defense is in one place (the
grant's refresh-time matrix)" — was read as covering the whole AS. It did
not: `/oauth/introspect` also acts on a `cnf` and was silently narrowing a
compound one to the intent-explicit winner, vouching (`active: true`) for a
binding the AS never issued.

The rule is now stated per surface, and both surfaces fail closed:

| Surface | Compound `cnf` outcome |
| --- | --- |
| Refresh grant (`grants/refreshToken.mts`) | `invalid_grant`, pre-matrix short-circuit |
| Introspection (`/oauth/introspect`) | `active: false`, before any response is built |
| `extractConfirmation` (claim-shape validator) | Narrows to `jkt` — unchanged |

`extractConfirmation` deliberately does **not** reject. It is a public
export describing claim shape, and rejection is an admission decision that
belongs to the surface doing the vouching. The two are kept apart by an
explicit predicate, `isCompoundConfirmation`, which both surfaces share so
the notion of "compound" cannot drift between them.

Rejecting rather than narrowing is the only safe direction here, and the
alternative is worth recording because it is the intuitive one: making
`extractConfirmation` return `undefined` for a compound `cnf` would cause
the handler to omit `cnf` while still answering `active: true`, so a
resource server would read a bound token as a plain bearer token and
enforce no proof-of-possession at all — weaker than the narrowing it was
meant to replace.

Note this is a consistency and evidence-preservation fix, not a patched
exploit: this AS cannot mint a compound `cnf`, so producing one requires
forging a JWT, and an attacker holding the signing key can mint a clean
single-mechanism token anyway.

### Bad

- **More types to learn.** A first-time reader of the oauth package
  now has to follow `TokenBinding`, `Confirmation`, and
  `TokenBindingMechanism` to understand what `cnf` means. The
  README updates in Wave 2 Phase 4 are the mitigation; long-term
  the abstraction is the *only* way to keep mechanism additions from
  needing a re-audit of unrelated code paths.
- **The `intentExplicit` hint is a hand-set boolean.** Mechanism
  authors have to know the convention. Today there are exactly two
  values (DPoP true, mTLS false). If a future mechanism is hard to
  classify, the spec will need to grow more dispatch policies.
- **Mechanism allowlist requires manual gate updates.** Each new
  mechanism added to bound-RT issuance must be added to
  `bindingIsX` predicates in `authorization.mts` + `refreshToken.mts`.
  Considered a `mechanism.bindRefreshToken: boolean` capability flag
  but rejected — the gate is a security boundary, not a per-mechanism
  preference, and changing it in two places is intentional friction.

### Neutral

- **`token_type` wire string stays mechanism-specific.** DPoP → "DPoP"
  (RFC 9449 §5 MUST), mTLS → "Bearer" (RFC 8705 §3, the cert IS the
  binding evidence, not the wire token type). This is RFC-driven and
  not a design choice we own.
- **Per-mechanism reference.conf removed.** `oauth.tokenBinding.dispatch-policy`
  used to be redeclared by every binding-mechanism module's
  reference.conf; now it lives in core's bundled reference.conf as
  the single source of truth. Operators who set the key in their
  `application.conf` are unaffected (HOCON `.withFallback()`
  precedence preserves operator overrides).

## Compliance & references

- RFC 9449 (DPoP) §5 — explicit-intent token binding via JWS header
  proof; `token_type: "DPoP"` on the wire.
- RFC 8705 (mTLS) §3 + §3.1 + §4 — sender-constrained ATs via the
  RFC 7800 `cnf.x5t#S256` confirmation; wire-level `token_type`
  stays "Bearer".
- RFC 7800 (cnf claim) — confirmation method registry. Today's union
  variants (`jkt`, `x5t#S256`) come from RFC 9449 / RFC 8705
  respectively, not from RFC 7800 itself.
- RFC 7662 (token introspection) §2.2 — introspect echoes `cnf` so
  downstream verifiers can require the right mechanism's proof at
  resource-server boundaries.

## Related ADRs

- `2026-04-30-config-schema-strict-defaults-from-hocon.md` — explains
  why the `oauth.tokenBinding.dispatch-policy` default ships in
  `packages/core/config/reference.conf` rather than as a
  `.default(...)` in `CoreConfigSchema`.
- `2026-05-13-reference-conf-shipping.md` — the shipping mechanism
  that made it possible for core's reference.conf to be the single
  source of truth for `oauth.tokenBinding.dispatch-policy`.

## Implementation history

- Wave 2 Phase 1 (`5cf72c31`) — `grantMiddleware` contribution kind
  retro; baseline for mechanism factories.
- Wave 2 Phase 2 (`15e9389d` + `5de82c75` + `98f5f3e7`) — DPoP
  package + replay store + cnf claim emission + DPoP refresh-time
  matrix (5 rows).
- Wave 2 Phase 3 (`f690c8a1` + `9f327b4f` + `ccf5d973`) — mTLS
  package + PKI chain validation + mTLS RT binding + mTLS refresh-
  time matrix (5 rows) + compound-cnf reject + mechanism allowlist
  generalization.
- Cross-mechanism dispatch refactor (`c324d8eb`, mid-Phase-3) —
  `tokenBindingMechanisms` contribution slot in core + composed
  `tokenBindingMw` + `DispatchPolicy` moved to core's bundled
  schema. Resolves the Phase 3 §11.4 "single mechanism per
  deployment" limitation discovered during Sub-PR 3b review.
- Wave 2 Phase 4 — end-to-end introspect cnf test, this ADR, README
  updates, CHANGELOG roll-up.
