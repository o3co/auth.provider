# Contributing

General contribution guidelines (PR process, code style, release policy) are
not written down yet. For now this file documents the extension points where
getting it wrong is expensive and the compiler will not stop you.

Repository-wide rules that apply to every change live in [AGENTS.md](AGENTS.md)
— notably: English-only source and commit messages, and TDD (write the failing
test first).

## Contents

- [Writing a new token-binding mechanism](#writing-a-new-token-binding-mechanism)

---

## Writing a new token-binding mechanism

A token-binding mechanism proves that whoever presents a token is the party it
was issued to. Two ship today: DPoP (`@o3co/auth-provider-dpop`) and mTLS
(`@o3co/auth-provider-mtls`). A third is a new package implementing
`TokenBindingMechanism` plus a `Module` contributing it.

The interface is small:

```ts
interface TokenBindingMechanism {
  readonly kind: string;
  readonly intentExplicit: boolean;
  extract(req: Request): Promise<TokenBinding | null>;
}
```

Most of what follows is not visible in that signature.

### 1. Contribute to `tokenBindingMechanisms`, never to `grantMiddleware`

Contribute the raw mechanism and let core compose it:

```ts
export const acmeModule = defineModule({
  name: "acme-binding",
  requires: [],
  optional: [],
  contributes: {
    tokenBindingMechanisms: [(deps) => createAcmeMechanism(deps)],
  },
});
```

Core collects every contributed mechanism into a **single** `tokenBindingMw`,
so the deployment's `DispatchPolicy` arbitrates across modules.

Mounting your own `tokenBindingMw` through the `grantMiddleware` slot — the
pre-v0.8 shape — puts a second middleware after the composed one. It assigns
`req.tokenBinding` unguarded, so it silently overrides whatever the composed
surface resolved, and the deployment's dispatch policy stops deciding
anything. Boot warns about this (`reason: "token_binding_surface_overlap"`),
but do not create the condition in the first place.

`grantMiddleware` remains correct for ordinary pre-dispatch middleware — rate
limiters, body pre-processing. It is only wrong as the mounting point for a
binding mechanism.

### 2. Choosing `kind`

`kind` is not a display name. It appears in three places that outlive your
package:

- **Error codes.** A throw from `extract` without a `code` field becomes
  `invalid_<kind>_proof`. Since OAuth error codes must match
  `/^[a-z][a-z0-9_]*$/`, `kind` must be lowercase snake_case — `acme_hw` gives
  `invalid_acme_hw_proof`; `AcmeHW` produces a malformed code.
- **`SenderConstraint.methods`.** Operators list kinds to require a binding on
  a client (`{ required: true, methods: ["dpop"] }`). Renaming `kind` later is
  a breaking change to their stored client records, not just to your package.
- **`TokenBinding.kind`**, which downstream grant code branches on.

Pick it as carefully as a public API name, because it is one.

### 3. Choosing `intentExplicit`

The question is **not** "is this mechanism strong?" It is: *can the signal
appear on a request the client did not deliberately construct?*

- `intentExplicit: true` — the signal only exists because the client built it.
  A DPoP proof header is constructed and signed per request; it cannot appear
  by accident.
- `intentExplicit: false` — the signal can be an ambient artifact of the
  transport. An mTLS cert is injected by a reverse proxy whether or not the
  client intended to bind anything.

Under the default `intent-explicit` policy an explicit mechanism wins over
ambient ones, and **two** succeeding explicit mechanisms are a `400
invalid_request` — the AS refuses to guess which binding the client meant.

Two known sharp edges:

- Get this backwards on an ambient mechanism (marking it explicit) and any
  request carrying both it and a real explicit proof becomes a 400 for
  well-behaved clients.
- Two succeeding **ambient** mechanisms currently resolve first-registered-wins
  rather than rejecting. That asymmetry is pinned in
  `packages/core/src/middleware/__tests__/tokenBinding.test.mts`; if yours is
  the second ambient mechanism to ship, decide deliberately whether first-wins
  is right and change the test if it is not. Do not let the existing behavior
  decide by default.

### 4. `extract` must be all-or-nothing

Return `null` when your signal is **absent** — that is not an error, it is a
request that simply is not using your mechanism.

Throw when the signal is **present but invalid**. Do not fall back, do not
return `null` to "let another mechanism handle it": throwing rejects the whole
request, and that is the point. A request carrying invalid binding material
must not be silently downgraded to whatever else happened to validate. This is
pinned end-to-end in
`packages/mtls/src/__tests__/dual-mechanism.integration.test.mts`.

That rejection is intentional even though it means a client that can inject a
malformed header into someone else's request can break it. Weakening it is a
security change, not a robustness fix.

Attach `code` to the thrown error when you want a specific OAuth error code;
it must match `/^[a-z][a-z0-9_]*$/`. Anything else falls back to
`invalid_<kind>_proof`, which is deliberate — it keeps infrastructure-layer
codes (`ECONNREFUSED` and friends) out of the public error envelope.

### 5. Land the refresh-time matrix in the SAME PR as the allowlist entry

This is the one that silently degrades security if you split it.

`packages/oauth/src/grants/refreshToken.mts` decides whether a refreshed
refresh token carries a `cnf` claim, gated on a mechanism allowlist
(`bindingIsDpop || bindingIsMtls` today). Adding your kind there without also
implementing its **refresh-time continuity matrix** means the AS issues a
bound RT whose binding nothing re-verifies at refresh — a token that looks
sender-constrained and is not.

So: the matrix and the allowlist entry land together, in one PR, or neither
does. Splitting them across PRs leaves the repository in a state where the
weaker half is already shipped.

Note also that a compound `cnf` — one carrying two mechanisms' confirmations —
is rejected on both AS surfaces (`invalid_grant` at refresh, `active: false` at
introspection). Your mechanism emits exactly one confirmation; do not design
around merging.

### Checklist

- [ ] Contributed via `tokenBindingMechanisms`, not `grantMiddleware`
- [ ] `kind` is lowercase snake_case and chosen as a permanent public name
- [ ] `intentExplicit` reflects whether the signal can appear without client
      intent — and, if ambient, the multi-ambient behavior was decided rather
      than inherited
- [ ] `extract` returns `null` only for absence, throws for invalid material
- [ ] Thrown `code` matches `/^[a-z][a-z0-9_]*$/`, or the fallback is intended
- [ ] Refresh-time matrix and the `refreshToken.mts` allowlist entry land in
      the same PR
- [ ] Integration test mounting your module alongside `dpopModule` and
      `mtlsModule`, covering both valid and invalid material

### Reference

- ADR: `packages/core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md`
  — cross-mechanism design rationale, per-surface compound-`cnf` policy, and
  the v0.7 `grantMiddleware` migration note
- Reference implementations: `packages/dpop` (explicit), `packages/mtls`
  (ambient)
