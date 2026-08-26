# Contributing

General contribution guidelines (PR process, code style, release policy) are
not written down yet. For now this file documents the extension points where
getting it wrong is expensive and the compiler will not stop you.

Repository-wide rules that apply to every change live in [AGENTS.md](AGENTS.md)
— notably: English-only source and commit messages, and TDD (write the failing
test first).

## Contents

- [Writing a new token-binding mechanism](#writing-a-new-token-binding-mechanism)
- [Writing an adapter builder that opens a connection](#writing-an-adapter-builder-that-opens-a-connection)

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

- **Error codes.** A throw from `extract` surfaces as `invalid_<kind>_proof`
  unless it carries a `code` that is a string matching `/^[a-z][a-z0-9_]*$/` —
  so a missing code and a malformed one (`"ECONNREFUSED"`, `"Invalid-Proof"`)
  both land on the fallback. `kind` must therefore be lowercase snake_case
  itself: `acme_hw` gives `invalid_acme_hw_proof`, while `AcmeHW` would emit a
  malformed code with nothing left to fall back to.
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
it must be a string matching `/^[a-z][a-z0-9_]*$/`. A missing code, a
non-string code, and a code that fails the pattern all fall back to
`invalid_<kind>_proof` — the check is a shape test, not a presence test. That
is deliberate: it keeps infrastructure-layer codes (`ECONNREFUSED` and
friends) out of the public error envelope by construction rather than by
asking every mechanism author to remember. The consequence to know is that a
typo'd code does not surface as itself; it silently becomes the fallback.

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
- [ ] Thrown `code` is a string matching `/^[a-z][a-z0-9_]*$/`, or the
      `invalid_<kind>_proof` fallback is the intended wire result
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

---

## Writing an adapter builder that opens a connection

Three things belong in a builder that dials something — a Redis client, a
database pool, anything holding a socket. All three are easy to leave out, none
of them fail loudly, and each has already shipped as a production incident.

```ts
factory.register("redis", async (config, ctx) => {
  const client = createClient({ url });

  // 1. Error listener, BEFORE connect().
  client.on("error", (err) => logger.error({ err }, "session_store_redis_error"));

  await client.connect();

  // 2. Cleanup.
  ctx.lifecycle?.register(async () => { await client.quit(); });

  // 3. Readiness probe.
  ctx.readiness?.register({ name: "session-store", check: () => client.ping() });

  return wrap(client);
});
```

### 1. Attach the `error` listener before connecting

Both node-redis and ioredis emit `error` on socket failures — including while
they are happily auto-reconnecting — and an EventEmitter `error` with no
listener **throws and takes the process down**. Redis is load-bearing for
sessions, codes, and refresh-token families in the deployable defaults, so a
failover blip crashed the identity provider.

Before `connect()`, not after: a connection that fails during the handshake
emits while `connect()` is still in flight, which is exactly the flapping
backend this guards against.

The listener's job is to make the event *observed*, not to implement retry —
the driver already does that. Log it as a named structured event and move on.

**This applies to connections you derive, too.** `ioredis.duplicate()` copies
options but **not** listeners, so a duplicate starts with zero. If your wrapper
opens a connection the caller never sees, the wrapper owns its listener.

### 2. Register cleanup on `ctx.lifecycle`

`AppHandle.dispose()` drains these in LIFO order. Without one, the connection
outlives the app and shutdown hangs on an open handle.

Disposal must never be the thing that fails. Wrap a `quit()` that can reject:

```ts
ctx.lifecycle?.register(async () => {
  try { await client.quit(); } catch { client.disconnect(); }
});
```

A rejecting disposal on an `await using` binding surfaces as a `SuppressedError`
that hides the real error, and can report failure for work that already
committed.

### 3. Register a readiness probe on `ctx.readiness`

The builder is the only place holding the connection: the adapter you return
exposes a narrow command surface with no `ping`, deliberately. Skip this and
`/readyz` answers `200` while your backend is unreachable — a failure that
looks exactly like success.

- `name` identifies the **resource**, not the module: `redis`, `session-store`,
  `database`. It appears in the readiness response body, so it is a public
  name.
- `check` resolves when reachable and throws when not. The return value is
  ignored; only settlement matters.
- **One probe per connection.** Six adapters sharing one socket get one probe —
  register where the connection is constructed, not in each consumed slot.
- Use optional chaining. A factory constructed outside the boot planner (unit
  tests) receives `{}` as its context.

Modules forwarding these declare them optional and pass both through:

```ts
optional: ["lifecycleRegistrar", "readinessRegistrar"],
// …
const ctx: BuilderContext = {
  lifecycle: deps.lifecycleRegistrar,
  readiness: deps.readinessRegistrar,
};
```

### Test the forwarding, not just the builder

The memory adapter registers nothing, so a test that exercises it passes
whether or not the module forwards the registrars. Delete
`readiness: deps.readinessRegistrar` and a suite covering only the memory path
stays green while the probe silently disappears. Cover the connecting adapter
with the driver mocked, and assert the probe arrives.

### Checklist

- [ ] `error` listener attached **before** `connect()`, logging a named event
- [ ] Listener attached to connections the wrapper derives (`duplicate()`)
- [ ] `ctx.lifecycle?.register` for cleanup, and the cleanup cannot reject
- [ ] `ctx.readiness?.register` with a resource-named probe
- [ ] One probe per connection, not per consumed slot
- [ ] The forwarding module declares both registrars in `optional`
- [ ] A test that fails if the forwarding is removed

### Reference

- ADR: `packages/core/docs/adr/2026-08-26-readiness-probes-registered-by-connection-owners.md`
- Reference implementations: `packages/session/src/store/factory.mts` (node-redis),
  `templates/standalone/src/modules.mts` `getOrCreateClients` (shared ioredis)
