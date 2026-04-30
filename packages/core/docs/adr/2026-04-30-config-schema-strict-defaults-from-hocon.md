# ADR 2026-04-30 — Config schema is a pure type contract; defaults live in hocon

## Status

Accepted (2026-04-30).

## Context

`packages/core/src/config/application.schema.mts` defines `CoreConfigSchema`
and `AppConfigSchema` (Zod). At the boundary, configuration also flows
through `packages/core/config/application.conf` (HOCON parsed by
`@o3co/ts.hocon`), which supplies values and applies `${?ENV_VAR}`
substitutions for operator overrides.

Until this change, both layers carried the same defaults:

```typescript
// schema
http: z.object({
  port: z.coerce.number().default(3000),
  trustProxy: z.boolean().default(false),
})
```

```hocon
# hocon
http {
  port = 3000
  port = ${?HTTP_PORT}
  trustProxy = false
  trustProxy = ${?HTTP_TRUST_PROXY}
}
```

This split caused real harm during `feat/v0.5.0-module-system-redesign`
(PR #97). A change to `federations.<name>.enabled` had to coerce env-var
strings (`"false"` → `false`) via `z.preprocess`, but Zod's `.default()`
inside a `preprocess` does not propagate the "optional" flag to the
enclosing object schema. That made the field effectively required at parse
time despite its visible `.default(false)`. CI failures on `federations:
{}` inputs surfaced the trap. Two fixes existed: hoist `.default(false)`
outside the preprocess (Option A — short-circuit), or remove the
schema-side default entirely and rely on hocon (Option C — root cause).

## Decision

Schemas in `application.schema.mts` describe the **shape** required at the
boundary. They do not carry runtime default values. All defaults live
exclusively in `packages/core/config/application.conf`. `${?ENV_VAR}`
substitutions in that file are the only override surface.

Concretely:

- Removed `.default(X)` from 21 locations in the schema where hocon already
  supplies the same value.
- Kept `optional()` for fields that are env-only and have no hocon default
  (e.g. `oauth.jwt.issuer`, `signingKey.local.{secret,privateKey,...}`,
  `endpoints.*.url`).
- Tests that previously relied on schema-side defaults to populate bare
  `{}` inputs now supply explicit values via the shared factory in
  `src/testing/fixtures/valid-config.mts`. The factory returns a
  minimal schema-valid baseline rather than a hocon mirror —
  `session.storage.type` is `memory` and `federations` is `{}` for
  test ergonomics, which intentionally diverges from
  `application.conf` (where `storage.type = "redis"` and a built-in
  `federations.google` block is shipped). The factory is exposed to
  consumer test code through the `./testing` subpath in
  `package.json#exports` (per A2-γ spec §6.1 + §7), so sibling
  packages and downstream applications can reuse the same baseline
  without copying it.

## Rationale

1. **Single Responsibility at the layer level.** The schema's job is type
   contract enforcement. The hocon layer's job is supplying values and
   reading env-var overrides. Mixing the two creates two sources of
   truth for the same fact, and they can drift silently.

2. **Eliminates a real trap.** The PR #97 incident demonstrated that
   schema-level defaults interact non-trivially with `z.preprocess`,
   `z.optional`, and surrounding `z.object` semantics. Removing
   schema-side defaults removes that interaction surface.

3. **Operator mental model is hocon-first.** Operators read
   `application.conf` to understand what the system does at runtime; a
   default that lives only in code (Zod) is invisible to them.

4. **Test fixtures become honest.** A test that asserts "this value is
   `3000`" now must explicitly supply `3000`, which forces the test to
   declare what it actually depends on rather than inheriting a hidden
   default.

## Consequences

### Positive

- Drift between schema defaults and hocon defaults is eliminated by
  construction.
- Failure modes from `.default()` interacting with `preprocess` /
  `optional` cannot recur at the schema layer.
- Adding a new config field requires a deliberate decision about which
  source supplies its default — not a copy-paste of the same value into
  two places.

### Negative

- Tests that need a parsable config must now supply every required leaf.
  Bare `{ http: {}, oauth: { jwt: {}, ... } }` inputs no longer parse.
  The shared fixture in `src/testing/fixtures/valid-config.mts`,
  re-exported from `@o3co/auth-provider-core/testing`, centralises this
  to prevent inline duplication across packages.
- A future contributor who adds `default(X)` back to the schema would
  re-introduce the drift hazard. This ADR plus the docstring at the top
  of `application.schema.mts` are the only guards against that
  regression.
- **I2 — library-consumer perspective.** Consumers that embed
  `@o3co/auth-provider-core` outside the standalone deployment shape
  (e.g. composing modules manually, loading config from TOML / env
  vars / an in-memory object instead of `application.conf`) are
  responsible for supplying the defaults that hocon would otherwise
  inject before passing the object to `validate()` /
  `composeConfigSchema().parse()`. The hocon-default coupling is
  intentional for the standalone deployment path, but library
  consumers see it as an additional integration constraint rather
  than a hidden default. The exported `makeValidCoreConfig` /
  `makeValidAppConfig` factories from
  `@o3co/auth-provider-core/testing` provide a reference baseline
  consumers can adapt; production consumers should encode their own
  defaulting layer rather than depend on test fixtures at runtime.
- **I4 — `federations.<name>.enabled` is now strict.** Pre-PR the
  schema-side `coerceBooleanFromEnv` carried `.default(false)`, but the
  composition with surrounding `z.preprocess` / `z.optional` / object
  shape was fragile: absent `enabled` sometimes parsed as `false` and
  sometimes caused boot to reject the entry outright (the trap that
  motivated this refactor — see Context). With the schema-side default
  removed, both branches collapse into a single contract: operators
  must write `enabled = true` / `enabled = false` explicitly inside
  each federation entry, or omit the entry entirely. Configurations
  that relied on a bare `federations { google {} }` shape now fail
  validation at boot deterministically. The hardening is intentional
  (no ambiguity about which providers are active) but is breaking and
  operator-visible; see `CHANGELOG.md` for the migration note.

### Neutral

- The hocon file `packages/core/config/application.conf` is now the
  single source of truth for defaults. Editing it is the only way to
  change the runtime default for a configurable field.

## Pattern preserved (env-only optional fields)

Fields that are optional and have no hocon-side default — only an
`${?ENV_VAR}` substitution — remain `z.string().optional()` in the
schema. Examples:

- `oauth.jwt.issuer`
- `oauth.jwt.signingKey.local.{secret,privateKey,privateKeyPath,publicKey,publicKeyPath}`
- `session.storage.redis.password`
- `endpoints.{login,client,authCallback}.url`

These are not "schema defaults"; they are valid-when-absent fields whose
absence is expected and meaningful (e.g. asymmetric key configurations
omit `secret`).

## How to apply this rule going forward

When adding a new config field:

1. Decide whether the field has a sensible default for "no operator
   intervention". If yes, supply that default in
   `application.conf` only — never in the schema.
2. If the field is env-only and absence is meaningful, mark it
   `z.<type>().optional()` in the schema and add `${?ENV_VAR}` (without a
   preceding default line) in `application.conf`.
3. Never add `.default(X)` to the schema. If a reviewer suggests it,
   point to this ADR.

## Related

- PR #97 (feat/v0.5.0-module-system-redesign) — surfaced the trap that
  motivated this ADR.
- This refactor's PR — implements the change across the schema and
  associated test fixtures.
