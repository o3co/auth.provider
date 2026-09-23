# boot

## Responsibility

The engine behind `createApp`: six stages in a fixed order — `validateManifests` → `planBoot` → `materializeComponents` → `applyContributions` → `freezeWorld` → `assembleApp` — that turn a list of manifests, the host's bootstrap components and the raw configuration into a frozen component world, a mounted Express router and an `AppHandle`. It owns manifest validation, the dependency graph and init order, provider activation, routing contributions to their collectors, freezing, route mount order, the middleware core mounts itself (protected-resource binding always; CORS only when `cors.allowedOrigins` is non-empty; the composed `tokenBindingMw` only when a mechanism was contributed), the discovery route's mounting, disposal, and the four bootstrap slots (`config`, `pathResolver`, `lifecycleRegistrar`, `readinessRegistrar`).

It owns no protocol behaviour: no grant, no route handler, no token. Provider-specific stage-1 checks — federation / redirect-policy pairing, MFA partial wiring, federation stores wiring, declared absence, grant-policy issuer, replica safety — are deliberately rows of boot's registry (o3co/auth.provider#368; F5 in #626), not code in the directories they concern: boot is the one place that sees every manifest and the parsed config together, and a registry row cannot be skipped by a module that forgot to call it.

## Public contract

- [`create-app.mts`](./create-app.mts) — `createApp(options)`; re-exported by [`../app.mts`](../app.mts) and the root barrel.
- [`types.mts`](./types.mts) — `CreateAppOptions`, `AppHandle`, `BootError` (line 1083) with `BootErrorReason` (26 literals), `BootStage` (six), one `*Details` type per reason, the collector contracts, and the `ComponentMap` augmentation for the bootstrap slots.
- [`validate-manifests.mts`](./validate-manifests.mts) — `STAGE_ONE_PRE_CONFIG_CHECKS` and `STAGE_ONE_POST_CONFIG_CHECKS` (exported, frozen), `validateManifests`, `checkMfaPartialWiring`, `checkFederationStoresWiring`.
- [`replica-safety.mts`](./replica-safety.mts) — `checkReplicaSafety`, `REPLICA_UNSAFE_MODULES`, `replicaUnsafeReason`.
- [`index.mts`](./index.mts) is the internal barrel; the root `index.mts` chooses the public subset. Package README: [App Factory](../../README.md#app-factory).

## Inputs and outputs

- `modules` are consumer code, taken as the erased `Module` type; boot validates their structure, never their behaviour. `bootstrapComponents` are host-owned and pre-seeded; `overrideComponents` replace a module's provider (the factory is skipped and the value's lifecycle stays the consumer's); `contributionKinds` supplies collectors for consumer-defined kinds only.
- Stage 1 composes every module's `configSchema` with core's, parses once, and substitutes the parsed config into `bootstrapComponents.config` for every later stage and every post-config check.
- Output: an `Object.freeze`d `AppHandle` whose `components` map is frozen, whose `routes` are in final mount order, and whose `readinessProbes` are what builders registered.
- Mutation stops at stage 5: the component map is frozen and every collector with a `freeze()` is sealed; `register` afterwards throws.

## Dependencies

- Imports from core: `modules/manifest` (types, `SYNTHETIC_COMPONENT_KEYS`), `modules/types` (`PathResolver`), `config/application.schema` (`composeConfigSchema`), `grants/registry` (the `GrantRegistry` behind the `grants` collector), `middleware/{cors,tokenBinding,protectedResourceBinding}`, `discovery/{planRoute,types,buildDocument}` (the last for the error it converts), `net/origin`, `adapters/AdapterFactory`, `readiness/*`, `logging/*`; `replica-safety.mts` imports every bundled `memory…Module` (`federation-grants/module`, `user-sessions/modules/memory`, …) to read its declaration. `express` is an optional peer: `create-app.mts` loads it with `await import("express")`, and `assemble-app.mts` falls back to `createRequire`.
- Imported by, outside `__tests__/`: `../app.mts`, `../index.mts`, `../testing/`. No other product code in core depends on boot (elsewhere, three wiring tests boot a real app through it and three adapter tests read `replicaUnsafeReason` from it); packages reach it only through `createApp`.
- F4 (#626, done): the dependency runs one way now. [`assemble-app.mts`](./assemble-app.mts) reads the issuer, the signing algorithms and the `discoveryMetadata` contributions out of its own frozen world, hands those three to [`planDiscoveryDocument`](../discovery/planRoute.mts) — the signing algorithms as a reader, so they are read only once both activation conditions have passed — and converts the `DiscoveryDocumentError` it may raise into a `BootError`. The `try` covers document planning and nothing else: [`discoveryRouteFor`](../discovery/planRoute.mts) builds the route afterwards, with the router factory (which comes from `options.express` or `createRequire`, not from the world), so a router-factory failure is never reported as a discovery misconfiguration whatever its type. Before that the step took this stage's world widened to `Record<string, unknown>` and cast three readings back out of it, and imported `BootError` to raise one — so a typed map was laundered through `unknown` and the two directories referenced each other. Of the three casts, two were only needed because the caller had widened its own typed `ComponentMap`; the third — the `discoveryMetadata` kind to its `ListCollector` — is on this side now, because mapping a contribution kind to its collector is what assembly knows.
- Must never import an adapter package or `testing/`.

## Invariants

- Stages 1 and 2 are deterministic and side-effect-free; stage 3 is async but deterministic for the same factory side effects (file headers; [`validate-manifests.test.mts`](./__tests__/validate-manifests.test.mts), [`plan-boot.test.mts`](./__tests__/plan-boot.test.mts)).
- Stage-1 rows run in registry order and the first violation wins (documented on `validateManifests`, not tested as such); each row has a unique id and a spec pointer, the documented order is kept, and the registry is frozen rows included — [`check-registry.test.mts`](./__tests__/check-registry.test.mts). The pairing check is the row `federation-redirect-policy-pairing` ([`validate-manifests.mts`](./validate-manifests.mts) line 1603) calling `checkFederationRedirectPolicyPairing` (line 775) — [`federation-pairing.test.mts`](./__tests__/federation-pairing.test.mts).
- A synthetic key can be neither provided, bootstrapped nor overridden — [`validate-manifests.test.mts`](./__tests__/validate-manifests.test.mts), step 3.
- Init order is topological with declaration order as tie-break; a cycle is `circular-dependency` at `planBoot`; an unused non-eager provider is never activated — [`plan-boot.test.mts`](./__tests__/plan-boot.test.mts).
- A provider runs at most once, in init order; an override skips it — [`materialize-components.test.mts`](./__tests__/materialize-components.test.mts).
- Name-keyed contributions register in init order; list-shaped ones append in input order; a name conflict runs no factory — [`apply-contributions.test.mts`](./__tests__/apply-contributions.test.mts).
- After `freezeWorld`, `GrantRegistry.register` throws `frozen` and `RouteCollector.append` throws — [`freeze-world.test.mts`](./__tests__/freeze-world.test.mts).
- Mount order honours `before` / `after`, a cycle is `route-order-cycle`, and factory-produced routes are collision-checked again at stage 6 — [`assemble-app.test.mts`](./__tests__/assemble-app.test.mts).
- The discovery route is an ordinary contribution: a colliding module route fails boot; a provider root without `jwks_uri` is a `BootError` wrapping `DiscoveryDocumentError` — [`discovery-aggregation.integration.test.mts`](./__tests__/discovery-aggregation.integration.test.mts). That wrapping is this stage's, and what the planner does with the values it is given is [`planRoute.test.mts`](../discovery/__tests__/planRoute.test.mts).
- An unfilled optional slot with an `AbsencePolicy` and no declaration refuses boot — [`declared-absence.test.mts`](./__tests__/declared-absence.test.mts), [`access-token-revocation-wiring.test.mts`](./__tests__/access-token-revocation-wiring.test.mts).
- `deployment.mode = "multi"` with a module declaring `replicaSafety` is refused naming every offender; unset warns; `"single"` is silent — [`replica-safety.test.mts`](./__tests__/replica-safety.test.mts); every memory-backed module declares — [`replica-safety.drift.test.mts`](./__tests__/replica-safety.drift.test.mts).
- A `grantPolicy` from any source is refused unless `oauth.jwt.issuer` is a non-empty string — [`composition-root-invariants.test.mts`](./__tests__/composition-root-invariants.test.mts); MFA and the federation stores are wired whole or not at all — [`mfa-partial-wiring.test.mts`](./__tests__/mfa-partial-wiring.test.mts), [`federation-stores-incomplete.test.mts`](./__tests__/federation-stores-incomplete.test.mts).
- Token-binding mechanisms compose into one middleware under the configured dispatch policy and a `null` factory is filtered — [`token-binding-mechanisms.integration.test.mts`](./__tests__/token-binding-mechanisms.integration.test.mts); `grantMiddleware` mounts before grant dispatch in registration order — [`grant-middleware.integration.test.mts`](./__tests__/grant-middleware.integration.test.mts).
- `BootErrorReason` is exactly 26 literals, `BootStage` exactly six, `AppHandle` exactly six keys — [`types.test.mts`](./__tests__/types.test.mts).

## Failure and lifecycle

- A refused boot is a `BootError` with `reason`, `stage` and typed `details`; `cause` is set for the `*-factory-failed` reasons and for `discovery-document-invalid`, which carries the `DiscoveryDocumentError` it wraps ([`discovery-aggregation.integration.test.mts`](./__tests__/discovery-aggregation.integration.test.mts)). The claim used to read "only for the `*-factory-failed` reasons", which was already false and became false *here* when #626 F4 moved the conversion into [`assemble-app.mts`](./assemble-app.mts). A required dependency missing at stage 3 or 4 is a plain `Error` — an invariant an earlier stage should have caught, not an operator problem.
- Partial rollback: a stage-3 failure runs the cleanups already recorded, in reverse, collecting cleanup errors into `details.cleanupErrors` — [`materialize-components.test.mts`](./__tests__/materialize-components.test.mts); `LifecycleRegistrar` cleanups drain when any later stage fails — [`create-app.test.mts`](./__tests__/create-app.test.mts).
- `dispose()` is single-shot. It runs `lifecycle.cleanup` in reverse-topological order, falls back to `Symbol.asyncDispose` for module-provided values that declared none — never for override or bootstrap values — and drains the `LifecycleRegistrar` in LIFO order; every error is aggregated into one `AggregateError` — [`assemble-app.test.mts`](./__tests__/assemble-app.test.mts), [`integration.test.mts`](./__tests__/integration.test.mts).
- No cancellation and no deadline: `CreateAppOptions` carries no signal, so a factory that never settles keeps `createApp` pending. Documented, not tested.

## Contract tests

[`__tests__/`](./__tests__/) — one file per stage plus the integration and wiring suites named above; all run under typecheck mode (`vitest.config.mts` includes `src/boot/**/*.test.mts`).
