# modules/manifest

Last updated: 2026-09-29

## Responsibility

The vocabulary a module is written in: `defineModule`, `ModuleSpec` / `Module`, `ComponentMap` / `ComponentKey`, `ProviderDeps` / `Provider`, `ContributesMap` with one factory type per contribution kind, the `RouteContribution` family, `ComponentLifecycle`, `ReplicaSafetyDeclaration`, `AbsencePolicy`, `ModuleSection` (a module's own configuration section) with `SectionSchema` / `SectionDeps`, and the synthetic-key set with its resolver projections.

Which mechanism a new policy is written on — a contribution that adds behaviour, a slot that fills a port, a contribution kind that changes a core decision, or, outside this vocabulary, a capability an adapter opts into — is chosen by the four axes in [AGENTS.md](../../../../../AGENTS.md#extension-surface-four-axes).

It decides nothing at runtime. `defineModule` returns its argument unchanged; every check on a manifest — uniqueness, closure, collisions, pairing, declared absence, replica safety — is a stage-1 row in [`../../boot/`](../../boot/README.md), and so is the parse of a module's section. It owns no slot's value type either: `ComponentMap` is an empty interface that the directory owning a value augments (`../../repositories/ClientRepository.mts` for `clientRepository`, `../../boot/types.mts` for `config` / `pathResolver` / the two registrars, `synthetic-keys.mts` for the resolvers).

It is separate from `boot/` so that a module is written against the vocabulary without the planner: this directory is its own package subpath (`./modules/manifest`) and is re-exported from the package root, which is where every package that authors a manifest imports it from, and the dependency runs one way — `boot/` imports it and it imports nothing of `boot/`.

## Public contract

- [`index.mts`](./index.mts) — the `@o3co/auth-provider-core/modules/manifest` subpath (`package.json#exports`); the root barrel re-exports the same names.
- One file per concept, named for it: `defineModule` is [`define-module.mts`](./define-module.mts), the contribution kinds [`contributes-map.mts`](./contributes-map.mts), the synthetic keys [`synthetic-keys.mts`](./synthetic-keys.mts), and so on.
- Package README: [Module System](../../../README.md#module-system).

## Inputs and outputs

- A manifest is consumer-authored data. `defineModule` neither validates nor freezes it; `readonly` at the type level is the contract, and boot freezes only its own projections.
- `ProviderDeps<R, O>`: a required key is `NonNullable<ComponentMap[K]>` because boot's requires-closure check guarantees it is present before any factory runs; an optional key may be `undefined`.
- Every factory in `provides`, `contributes` and `overrides` receives the module's one typed deps object; there is no per-contribution declaration.
- A module's own configuration section ([#728](https://github.com/o3co/auth.provider/issues/728)) is the manifest's `section` ([`module-section.mts`](./module-section.mts)): `schema`, the Zod schema of the one section the module owns; `reference`, the package's `config/reference.conf` as a `file:` URL; `at`, the dot-separated path the section sits at until it moves under the module's name (unset, the top-level key named exactly as the module is); `relocatedFrom`, the paths it moves from. Boot parses the value at `at` with the schema and hands the result to every factory as `deps.section`, typed as the schema's output; a module that declares no section has no `section` key, and reading it does not compile. `reference` and `relocatedFrom` are declarations boot does not act on yet: it neither layers the references nor refuses the old paths.
- `section` is not a slot. `ProviderDeps<R, O, S>` adds it beside the slots when `S`, the schema's type, is given; `defineModule` infers `S` from `section.schema`, and a call that writes its type arguments names it as the third. `Module` erases it with the widest schema, `SectionSchema`, whose deps read `section: never`, so a sectioned manifest is assignable to `Module` like any other.
- `configSchema` is deprecated in favour of `section`. It still composes with core's schema into the one parse of the whole configuration, as before.
- Name-keyed kinds (`grants`, `federations`, `tokenExchangeValidators`, `mfaFactors`, `sessionRequirements`) collide by name; list-shaped kinds (`auditHooks`, `routes`, `grantPolicyHooks`, `grantMiddleware`, `tokenBindingMechanisms`, `discoveryMetadata`) accumulate. Boot enforces the policy in its stage-1 rows `per-kind-contribute-duplicates` and `route-collisions`.
- Every contribution value type is the contract it will be read as, so registration and use share one type. That includes `FederationProvider` ([`../../federations/types.mts`](../../federations/types.mts)) and `ExchangeTokenValidator` ([`../../token-exchange/validator.mts`](../../token-exchange/validator.mts)), whose contracts are in core because boot collects them and core imports no sibling package: the type a contribution is registered with is the type its consumer reads. A factory may answer with the value or a promise of it (`Contributed<T>`) — `applyContributions` awaits it.
- `AbsencePolicy` is data — a config path, the one value that counts as the declaration, and an operator-facing hint. Boot's `declared-absence` row compares it with `===`.

## Dependencies

- Depends on, all type-only: `audit/`, `mfa/`, `policy/`, `grants/`, `federations/`, `token-exchange/` and `session-admission/` (the contribution value types, and the branded resolver type), `discovery/` (the `discoveryMetadata` value type), `middleware/` (the `tokenBindingMechanisms` value type), `express`, `zod`. Nothing from `boot/` and no implementation.
- Depended on by `boot/`, by every bundled `…Module` in core (directly or through `../index.mts`), by `discovery/`, `device-authorization/` and `grants/` for types, and by every downstream package that authors a manifest.
- Direction: `boot` → `manifest`, never the reverse. This directory must not import `boot/`, an adapter package, or `testing/`.

## Invariants

Type-level, checked by the TypeScript checker under vitest's typecheck mode (`vitest.config.mts` includes `src/modules/manifest/**/*.test.mts`); a green `vitest run` alone proves nothing about them.

- `SYNTHETIC_COMPONENT_KEYS` holds exactly eight keys, is `Object.freeze`d and typed `ReadonlySet<string>`; the resolvers expose only `get` and `entries` — [`synthetic-keys.test.mts`](./__tests__/synthetic-keys.test.mts), [`synthetic-keys-a5.test.mts`](./__tests__/synthetic-keys-a5.test.mts).
- `ComponentMap` carries no `*Base` legacy slot — [`component-map.test.mts`](./__tests__/component-map.test.mts), [`legacy-slots-absent.test.mts`](./__tests__/legacy-slots-absent.test.mts).
- `Module` is `ModuleSpec<ComponentKey, ComponentKey, SectionSchema>`, so any authored manifest is assignable; `ModuleSpec` has eleven readonly fields — [`module-spec.test.mts`](./__tests__/module-spec.test.mts).
- `ProviderDeps` derives the required + optional shape, strips `| undefined` from required slots, and adds `section` typed as the schema's output only when a section schema is given — [`provider.test.mts`](./__tests__/provider.test.mts).
- The `const` generic inference of literal `requires` / `optional` without `as const` is proven on a local mirror (`defineLocalModule`), and the real `defineModule`'s signature by a compile smoke check. The real `defineModule` infers the section's schema: `deps.section` is its output in every `provides`, `contributes` and `overrides` factory, a module without a section has no `deps.section`, a sectioned manifest is still a `Module`, and `section.schema` must be a Zod schema — [`define-module.test.mts`](./__tests__/define-module.test.mts).
- `ContributesMap` has the seven base kinds plus `grantMiddleware`, `tokenBindingMechanisms`, `discoveryMetadata` and `sessionRequirements`; list-shaped kinds are readonly arrays, name-keyed kinds readonly records — [`contributes-map.test.mts`](./__tests__/contributes-map.test.mts).
- `RouteContribution` / `RouteAdvertisement` / `HttpMethod` — [`route-contribution.test.mts`](./__tests__/route-contribution.test.mts), [`route-contribution.types.test.mts`](./__tests__/route-contribution.types.test.mts); `ComponentLifecycle` — [`lifecycle.types.test.mts`](./__tests__/lifecycle.types.test.mts).
- Every contribution kind's value type is its concrete contract — `GrantHandler`, `AuditSink`, `MfaFactor` (`../../mfa/factor.mts`), `SessionRequirement` (`../../session-admission/requirement.mts`), `GrantPolicyHook`, `FederationProvider`, `ExchangeTokenValidator` — each asserted identical to its contract, and a module contributing a federation without its methods does not compile — [`../../__tests__/contributes-map-substitution.test.mts`](../../__tests__/contributes-map-substitution.test.mts) (typecheck-included).
- Documented here, tested in boot: the collision policy ([`../../boot/__tests__/validate-manifests.test.mts`](../../boot/__tests__/validate-manifests.test.mts)), that an `absencePolicies` key must appear in `requires` / `optional` ([`../../boot/__tests__/declared-absence.test.mts`](../../boot/__tests__/declared-absence.test.mts)), and how a section is read, parsed, refused and delivered ([`../../boot/__tests__/module-section.test.mts`](../../boot/__tests__/module-section.test.mts)).

## Failure and lifecycle

Nothing here fails at runtime. A manifest violation is a `BootError` from stage 1, and so is a section its schema refuses (`config-validation-failed`, naming the operator's path); a `ComponentLifecycle.cleanup` runs at `AppHandle.dispose()` in reverse-topological order with errors aggregated (boot README). A `grantMiddleware`, `tokenBindingMechanisms` or `mfaFactors` factory that returns `null` means "disabled by config": the first two are skipped at composition, and an `mfaFactors` kind is claimed and absent from `mfaFactorResolver` ([`../../mfa/__tests__/factorResolver.test.mts`](../../mfa/__tests__/factorResolver.test.mts)) — [`../../boot/__tests__/grant-middleware.integration.test.mts`](../../boot/__tests__/grant-middleware.integration.test.mts), [`../../boot/__tests__/token-binding-mechanisms.integration.test.mts`](../../boot/__tests__/token-binding-mechanisms.integration.test.mts).

## Contract tests

[`__tests__/`](./__tests__/) — the type-level tests listed above. Behavioural guarantees over a manifest are boot's and live in [`../../boot/__tests__/`](../../boot/__tests__/).
