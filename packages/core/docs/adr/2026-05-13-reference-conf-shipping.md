# ADR 2026-05-13 — Library-shipped `reference.conf` + 3-tier withFallback chain

## Status

Accepted (2026-05-13). Extends ADR `2026-04-30-config-schema-strict-defaults-from-hocon.md`.

## Context

ADR 2026-04-30 established that HOCON `application.conf` is the single source of truth for
runtime defaults and Zod schemas carry no `.default(X)`. At that time
`packages/core/config/application.conf` was treated as the library default — but it was never
shipped to consumers via npm (the package `files` field excluded it). Consumers reading config
in their composition root therefore had no library-default layer; the
`templates/standalone/config/application.conf` template carried a full inline copy of every
default, and operators saw library values and deployment values mixed in one file with no clear
separation.

This left two gaps:

1. **Library defaults could not evolve safely.** A change to a default in the in-repo
   `application.conf` did not propagate to consumers; they continued to run whatever values their
   copy of the template had at install time.

2. **The `feedback_secure_default_opt_in` discipline could not be enforced.** "Library ships
   `enabled = false`, consumer opts in to `enabled = true`" requires a library layer that
   consumers actually merge against at runtime. Without it, the only way to enforce default-off
   was the strict-required pattern from ADR I4 (federations) — operationally heavy and not a
   universal posture.

A third problem emerged from the implicit `!== false` check in `oauthAuthorizationModule` grant
registration. HOCON `${?ENV_VAR}` substitution returns a string when the variable is set, so
`OAUTH_GRANTS_<GRANT>_ENABLED=false` produced the string `"false"` in the parsed config object.
`"false" !== false` is `true`, so the grant was silently left enabled despite the env override.

## Decision

1. **Ship `reference.conf` as the library's declarative defaults layer.** Rename
   `packages/core/config/application.conf` to `packages/core/config/reference.conf`. Add
   `config/` to `package.json#files` and add the `./reference.conf` subpath to
   `package.json#exports` so consumers can resolve it via
   `import.meta.resolve("@o3co/auth-provider-core/reference.conf")`.

2. **Standalone composition root builds a 3-tier HOCON precedence chain:** `{env}.conf` over
   `application.conf` over `reference.conf` (the template's `application.conf` is the
   consumer-delta layer; `{env}.conf` carries per-deployment-environment overrides).
   Implemented via:

   ```typescript
   parseFile(envConf)
     .withFallback(parseFile(applicationConf))
     .withFallback(parseFile(referenceConf))
   ```

3. **Apply the secure-default baseline in `reference.conf`:** all built-in OAuth grants default
   `enabled = false` (consumer opts in per-deployment); `rateLimit.failMode` defaults to
   `"closed"` (secure load shedding under limiter-backend errors). `federations.*` provider
   entries are NOT declared in `reference.conf` — federation declarations are consumer territory
   and live in the template's `application.conf` or the operator's own config.

4. **Code path is strict opt-in:** `oauthAuthorizationModule` checks
   `grantsCfg.X?.enabled === true` (not `!== false`). This handles three cases atomically:
   (a) absent keys in the config object, (b) explicit HOCON `enabled = false`, and (c) the
   string `"false"` produced by HOCON env-var substitution — all correctly treated as disabled.
   The strict check restores the intended env-disable behavior that the previous `!== false`
   check could not provide.

5. **Template's `application.conf` becomes delta-only:** keys that match `reference.conf`
   verbatim are dropped, reducing the operator-visible surface to deployment-specific decisions.
   A guidance comment at the top of the template points operators at the library baseline.
   For each grant the template enables, the env-substitution line
   (`enabled = ${?OAUTH_GRANTS_*_ENABLED}`) is repeated at the template layer so env-var
   overrides still reach the resolved config — HOCON precedence means an env substitution only
   in `reference.conf` would be shadowed by the template layer's explicit value.

## Consequences

### Positive

- Library defaults evolve via npm package upgrades. Consumers resolving `reference.conf` via
  `import.meta.resolve` automatically pick up the updated baseline on their next install.
- The `feedback_secure_default_opt_in` discipline is now operationally enforceable: the library
  ships `enabled = false`, the consumer opts in by writing `enabled = true` in their own
  `application.conf`.
- Operator-readable config narrows to deployment-specific values; the library baseline is
  locatable in one well-known place (`@o3co/auth-provider-core/reference.conf`).
- The strict `=== true` check eliminates the silent env-disable regression that existed under
  `!== false` + HOCON env-substitution string return.

### Negative / trade-offs

- **Bundled deployments must externalize the asset.** Single-file ESBuild bundles, serverless
  packaging, and runtimes that cannot read raw files from `node_modules` need to copy or
  include the raw `reference.conf` themselves. The library does not promise bundler
  compatibility for this asset; direct Node runtime execution via ESM is the supported path.

- **`import.meta.resolve` is Node Stability 1.2 (release candidate)** as of Node 20.x.
  The sync form became available in Node 20.6 without the `--experimental-vm-modules` flag.
  Node Stability 1.2 means the API is expected not to change and is effectively frozen pending
  promotion to Stable (2), but has not yet received the final graduation mark. If the sync form
  is altered, the standalone resolver gains a
  `createRequire(import.meta.url).resolve(...)` fallback. Not required for the current cycle
  but flagged here.

- **`federations.*` strict-required pattern from ADR I4 is preserved.** Federation declarations
  remain consumer territory: `reference.conf` carries an empty `federations {}` block (to
  satisfy the `AppConfigSchema` record shape) but declares no providers. Consumer-side
  `application.conf` declarations layer over via `withFallback`.

### Migration notes

- Consumers running the standalone template inherit the new default-off baseline through the
  `withFallback` chain automatically. If `application.conf` already opts in to `session` /
  `authorization_code` / `refresh_token`, no change is needed.
- Custom composition roots (not using the standalone template) should add the library reference
  as the bottom-of-stack fallback:
  `parseFile(env).withFallback(parseFile(application)).withFallback(parseFile(libraryRef))`,
  where `libraryRef = fileURLToPath(import.meta.resolve("@o3co/auth-provider-core/reference.conf"))`.
- The in-repo file `packages/core/config/application.conf` has been renamed to `reference.conf`.
  Any custom tooling or scripts that read that path need to be updated.

## Implementation reference

- Spec: `.claude/superpowers/specs/2026-05-13-reference-conf-shipping.md`
- PR commits: TBD (filled in at release tag time per release-policy R6 step 5).

## Related

- ADR `2026-04-30-config-schema-strict-defaults-from-hocon.md` — establishes HOCON as the
  single source of truth for runtime defaults. This ADR extends that decision by making the
  library's HOCON layer consumer-reachable via npm.
- `feedback_secure_default_opt_in` — "shipped HOCON ships built-in modules default off; consumer
  explicitly opts in."
