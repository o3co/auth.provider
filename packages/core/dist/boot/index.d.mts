/**
 * boot/index.mts — Internal barrel for the A2-β boot planner package.
 *
 * Re-exports the orchestrator (`createApp`) and the complete type surface
 * from `types.mts` (intermediate stage types, `AppHandle`, `BootError` class,
 * `BootErrorReason`, `BootStage`, all per-reason `*Details` interfaces,
 * and collector contracts).
 *
 * The package root `index.mts` selectively re-exports the subset of these
 * symbols that forms the public API. Phase 9 (A2-γ caller migration) deleted
 * the legacy v0.4.x `createApp` body and the `createBootApp` coexistence
 * alias; the package root's `createApp` now resolves to this orchestrator
 * directly via `./app.mjs`.
 *
 * Per A2-β §6.4 / §9.
 */
export { createApp } from "./create-app.mjs";
export type { AppHandle, BootErrorDetails, BootErrorReason, BootStage, BootstrapComponentCollisionDetails, BootstrapMap, CircularDependencyDetails, CleanupRecord, CollectedRouteContribution, ComponentWorld, ConfigValidationFailedDetails, ContributeAndOverrideSameKeyDetails, ContributeFactoryFailedDetails, ContributionCollectorMap, ContributionEntry, ContributionKind, ContributionKindMap, CreateAppOptions, DefaultBootstrapMap, DepsBlueprint, DuplicateContributeDetails, DuplicateModuleNameDetails, DuplicateOverrideDetails, DuplicateProvidesDetails, FederationRedirectPolicyUnpairedDetails, FrozenWorld, InvalidRouteAdvertisementPathDetails, LifecycleWithoutProvidesDetails, ListCollector, ListShapedOverrideDetails, MissingRequiredComponentDetails, NameKeyedCollector, NormalisedModule, OrderedRouteContribution, OverrideTargetMissingDetails, ProviderActivation, ProvidesFactoryFailedDetails, RegistryWorld, RouteCollector, RouteOrderCycleDetails, RouteOrderTargetMissingDetails, SyntheticKeyCollisionDetails, UnknownContributionKindDetails, ValidatedManifests, ValidatedModule, } from "./types.mjs";
export { BootError } from "./types.mjs";
//# sourceMappingURL=index.d.mts.map