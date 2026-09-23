# modules/manifest

## Responsibility

The vocabulary a module is written in: `defineModule`, `ModuleSpec` / `Module`, `ComponentMap` / `ComponentKey`, `ProviderDeps` / `Provider`, `ContributesMap` with one factory type per contribution kind, the `RouteContribution` family, `ComponentLifecycle`, `ReplicaSafetyDeclaration`, `AbsencePolicy`, and the synthetic-key set with its two resolver projections.

It decides nothing at runtime. `defineModule` returns its argument unchanged; every check on a manifest — uniqueness, closure, collisions, pairing, declared absence, replica safety — is a stage-1 row in [`../../boot/`](../../boot/README.md). It owns no slot's value type either: `ComponentMap` is an empty interface that the directory owning a value augments (`../../repositories/ClientRepository.mts` for `clientRepository`, `../../boot/types.mts` for `config` / `pathResolver` / the two registrars, `synthetic-keys.mts` for the resolvers).

## Public contract

- [`index.mts`](./index.mts) — the `@o3co/auth-provider-core/modules/manifest` subpath (`package.json#exports`); the root barrel re-exports the same names.
- [`define-module.mts`](./define-module.mts), [`module-spec.mts`](./module-spec.mts), [`component-map.mts`](./component-map.mts), [`provider.mts`](./provider.mts), [`contributes-map.mts`](./contributes-map.mts), [`route-contribution.mts`](./route-contribution.mts), [`absence-policy.mts`](./absence-policy.mts), [`synthetic-keys.mts`](./synthetic-keys.mts).
- Package README: [Module System](../../../README.md#module-system).

## Inputs and outputs

- A manifest is consumer-authored data. `defineModule` neither validates nor freezes it; `readonly` at the type level is the contract, and boot freezes only its own projections.
- `ProviderDeps<R, O>`: a required key is `NonNullable<ComponentMap[K]>` because boot's requires-closure check guarantees it is present before any factory runs; an optional key may be `undefined`.
- Every factory in `provides` and `contributes` receives the module's one typed deps object; there is no per-contribution declaration.
- Name-keyed kinds (`grants`, `federations`, `tokenExchangeValidators`, `mfaFactors`) collide by name; list-shaped kinds (`auditHooks`, `routes`, `grantPolicyHooks`, `grantMiddleware`, `tokenBindingMechanisms`, `discoveryMetadata`) accumulate. Boot enforces the policy (its stage-1 steps 6 and 7).
- Every contribution value type is the contract it will be read as. `FederationProvider` ([`../../federations/types.mts`](../../federations/types.mts)) and `ExchangeTokenValidator` ([`../../token-exchange/validator.mts`](../../token-exchange/validator.mts)) were `unknown` until #626 P1, because their contracts lived in `packages/session` and `packages/oauth-token-exchange`, which core may not import; they moved into core, so registration and use share one type and the casts consumers carried are gone. A factory may answer with the value or a promise of it (`Contributed<T>`) — `applyContributions` awaits it.
- `AbsencePolicy` is data — a config path, the one value that counts as the declaration, and an operator-facing hint. Boot's `declared-absence` row compares it with `===`.

## Dependencies

- Imports, all type-only: `../../audit/types`, `../../mfa/types`, `../../policy/types`, `../../grants/types` (four of the substituted contribution value types), `../../federations/types` and `../../token-exchange/validator` (the two #626 P1 moved in), `../../discovery/types` (the `discoveryMetadata` value type), `../../middleware/tokenBinding` (the `tokenBindingMechanisms` value type), `express`, `zod`. Nothing from `boot/` and no implementation.
- Imported by every stage in `boot/`, by every bundled `…Module` in core (`../../user-sessions/modules/memory.mts`, `../../access-token-denylist/module.mts`, …), by `../../discovery/planRoute.mts`, `../../device-authorization/types.mts` (`AbsencePolicy`), and by every downstream package that authors a manifest.
- Direction: `boot` → `manifest`, never the reverse. This directory must not import `boot/`, an adapter package, or `testing/`.

## Invariants

Type-level, checked by the TypeScript checker under vitest's typecheck mode (`vitest.config.mts` includes `src/modules/manifest/**/*.test.mts`); a green `vitest run` alone proves nothing about them.

- `SYNTHETIC_COMPONENT_KEYS` holds exactly six keys, is `Object.freeze`d and typed `ReadonlySet<string>`; the resolvers expose only `get` and `entries` — [`synthetic-keys.test.mts`](./__tests__/synthetic-keys.test.mts), [`synthetic-keys-a5.test.mts`](./__tests__/synthetic-keys-a5.test.mts).
- `ComponentMap` carries none of the v0.4.x `*Base` legacy slots — [`component-map.test.mts`](./__tests__/component-map.test.mts), [`legacy-slots-absent.test.mts`](./__tests__/legacy-slots-absent.test.mts).
- `Module` is `ModuleSpec<ComponentKey, ComponentKey>`, so any authored manifest is assignable; `ModuleSpec` has ten readonly fields — [`module-spec.test.mts`](./__tests__/module-spec.test.mts).
- `ProviderDeps` derives the required + optional shape and strips `| undefined` from required slots — [`provider.test.mts`](./__tests__/provider.test.mts).
- The `const` generic inference of literal `requires` / `optional` without `as const` is proven on a local mirror (`defineLocalModule`), and the real `defineModule`'s signature by a compile smoke check — [`define-module.test.mts`](./__tests__/define-module.test.mts).
- `ContributesMap` has the seven base kinds plus `grantMiddleware`, `tokenBindingMechanisms` and `discoveryMetadata`; list-shaped kinds are readonly arrays, name-keyed kinds readonly records — [`contributes-map.test.mts`](./__tests__/contributes-map.test.mts).
- `RouteContribution` / `RouteAdvertisement` / `HttpMethod` — [`route-contribution.test.mts`](./__tests__/route-contribution.test.mts), [`route-contribution.types.test.mts`](./__tests__/route-contribution.types.test.mts); `ComponentLifecycle` — [`lifecycle.types.test.mts`](./__tests__/lifecycle.types.test.mts).
- The two deferred types are still `unknown` — pinned in [`../../__tests__/contributes-map-substitution.test.mts`](../../__tests__/contributes-map-substitution.test.mts) (lines 74 and 79) so that a substitution is a deliberate change, not a drift.
- Documented here, tested in boot: the collision policy ([`../../boot/__tests__/validate-manifests.test.mts`](../../boot/__tests__/validate-manifests.test.mts), steps 6–7) and that an `absencePolicies` key must appear in `requires` / `optional` ([`../../boot/__tests__/declared-absence.test.mts`](../../boot/__tests__/declared-absence.test.mts)).

## Failure and lifecycle

Nothing here fails at runtime. A manifest violation is a `BootError` from stage 1; a `ComponentLifecycle.cleanup` runs at `AppHandle.dispose()` in reverse-topological order with errors aggregated (boot README). A `grantMiddleware` or `tokenBindingMechanisms` factory that returns `null` means "disabled by config" and is skipped at composition — [`../../boot/__tests__/grant-middleware.integration.test.mts`](../../boot/__tests__/grant-middleware.integration.test.mts), [`../../boot/__tests__/token-binding-mechanisms.integration.test.mts`](../../boot/__tests__/token-binding-mechanisms.integration.test.mts).

## Contract tests

[`__tests__/`](./__tests__/) — the type-level tests listed above. Behavioural guarantees over a manifest are boot's and live in [`../../boot/__tests__/`](../../boot/__tests__/).
