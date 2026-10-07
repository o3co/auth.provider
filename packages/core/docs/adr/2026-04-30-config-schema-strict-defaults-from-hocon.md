# ADR 2026-04-30 — Config schema is a pure type contract; defaults live in hocon

## Status

Accepted (2026-04-30). Amended 2026-10-07 (whose schema a section is, and who reads the
whole configuration: see the end of Decision).

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

Amended 2026-10-07 ([#728](https://github.com/o3co/auth.provider/issues/728),
B12). The schemas above are no longer one schema over the whole
configuration that every module reads. Each module declares the schema of
its own section, at its name; boot parses that section and hands it to the
module as `deps.section`, and core's schema declares `core {}` alone. The
whole configuration, the `config` slot, is core's: only the module objects
core ships read it, and boot refuses any other module that lists it in its
`requires` or its `optional`, switched on or not, before any factory runs
(`reserved-component-key`, naming the module and the slot). What this ADR
decides holds for every section's schema: it describes a shape and carries
no default; the defaults live in the `reference.conf` of the package that
owns the section (ADR 2026-05-13).

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

## Amendment 2026-10-07 — sections owned by modules, defaults in each package's reference.conf

Amended 2026-10-07 (#728). The rule stands: a schema states the shape, and
HOCON supplies the values. What it applies to has changed.

- **No application-wide schema.** `AppConfigSchema`, `fullSectionsSchema`
  and `composeConfigSchema` are removed. `CoreConfigSchema` declares core's
  own section, `core {}`, alone. Every other top-level section belongs to the
  module named after it, which declares the section's schema in its manifest
  (`section.schema`). Boot parses `core {}` with `CoreConfigSchema` and each
  loaded module's section with that module's schema, and hands the module
  the result (`deps.section`). The configuration is checked by the schemas
  of the packages a composition loads, composed at boot, and not by one
  schema that knows every package. A section no loaded module owns is not
  parsed.
- **Strict per section.** Each section refuses, at every object level, a
  key it does not declare, naming its path. A level whose keys are open by
  design (a record keyed by names the deployment chooses) is listed with
  its reason. `sectionStrictnessProblems` (`@o3co/auth-provider-core/testing`)
  is the check: core's tests run it over core's modules, and
  `tools/composition` over every package's.
- **Defaults per package.** "Defaults live in `application.conf` only" now
  reads: a section's defaults live in the `config/reference.conf` of the
  package that owns the section (core's own file for `core {}` and core's
  modules). The module names the file (`section.reference`), and the
  composition root layers it beneath the deployment's files (ADR 2026-05-13,
  amended the same day). A module's section schema carries no `.default`,
  `.prefault` or `.catch`.
- **Where a schema keeps a default.** Two kinds of path keep one. The first
  is a section that an exported function also parses as the operator wrote
  it, with no `reference.conf` beneath:
  `resolveRedisFederationGrantStoreOptions` and
  `resolveRedisFederationGrantIntentStoreOptions`. The second is a tuning
  key inside a block that stays absent until the operator writes it:
  `mtls.fullPki.revocation`, which `reference.conf` cannot hold without
  making the block present. The file still holds the same value wherever it
  holds the path.
- **The guard.** The negative consequence above ("this ADR plus the
  docstring … are the only guards") no longer holds for module sections.
  `tools/composition`'s section guard walks every module's section schema
  and fails on any value the schema fills. Its allow-list names each path
  above with its reason, and it also fails on an entry that matches no
  default, so the list can only shrink.
- **Library consumers (I2).** A composition root that does not use the
  standalone template supplies defaults by layering the files
  `moduleReferences(modules)` names for the modules it loads. It no longer
  passes a whole configuration through a composed schema.
