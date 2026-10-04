/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * boot/types.mts: every type the boot planner's stages share, and the
 * BootError catalogue. One file, because the `BootError.details` union and the
 * chained stage types would otherwise force circular imports between the
 * stage modules.
 */

import type { Server as HttpServer } from "node:http";
import { type InspectOptions, inspect } from "node:util";
import type { RequestHandler, Router } from "express";
import type { z } from "zod";
import type { LifecycleRegistrar } from "../adapters/AdapterFactory.mjs";
import type { AppConfig } from "../config/application.schema.mjs";
import type { OidcDiscoveryContribution } from "../discovery/types.mjs";
import { loggableError } from "../logging/loggableError.mjs";
import type { TokenBindingMechanism } from "../middleware/tokenBinding.mjs";
import type { ComponentKey, ComponentMap } from "../modules/manifest/component-map.mjs";
import type {
	AuditHook,
	Contributed,
	ExchangeTokenValidator,
	FederationInstance,
	FederationProvider,
	GrantHandler,
	GrantPolicyHookContribution,
	MfaFactor,
} from "../modules/manifest/contributes-map.mjs";
import type { Module } from "../modules/manifest/module-spec.mjs";
import type { HttpMethod, RouteContribution } from "../modules/manifest/route-contribution.mjs";
import type { PathResolver } from "../modules/types.mjs";
import type { RateLimitSpec } from "../ratelimit/types.mjs";
import type { ReadinessProbe, ReadinessRegistrar } from "../readiness/types.mjs";
import type { AdmissionAction } from "../session-admission/actions.mjs";
import type { RegisteredRequirement } from "../session-admission/requirement.mjs";

// ---------------------------------------------------------------------------
// ComponentMap bootstrap slots
// ---------------------------------------------------------------------------
//
// `config` and `pathResolver` are the two slots every createApp call must
// receive from the host (`DefaultBootstrapMap`). They are declaration-merged
// into ComponentMap here, where they originate, so DefaultBootstrapMap
// satisfies `B extends BootstrapMap` and modules can name them in `requires`.
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly config: AppConfig;
		readonly pathResolver: PathResolver;
		/**
		 * Boot-planner-owned lifecycle registrar, seeded before any module factory
		 * runs. A module that creates disposable sub-resources (Redis clients,
		 * interval timers) declares `optional: ["lifecycleRegistrar"]` and passes
		 * it as `createAdapterFactory(kind, { lifecycle: deps.lifecycleRegistrar })`,
		 * so each builder gets it as `BuilderContext.lifecycle`. A host cannot
		 * supply it (`bootstrap-component-collision`).
		 */
		readonly lifecycleRegistrar: LifecycleRegistrar;
		/**
		 * Boot-planner-owned readiness registrar, seeded and wired like
		 * `lifecycleRegistrar` (`{ readiness: deps.readinessRegistrar }`), so a
		 * builder can register a probe for the connection it opens. A host cannot
		 * supply it: a second registrar would collect probes the planner never
		 * reads, and `/readyz` would report ready while the dependency is down.
		 * See ADR 2026-08-26-readiness-probes-registered-by-connection-owners.
		 */
		readonly readinessRegistrar: ReadinessRegistrar;
	}
}

// ---------------------------------------------------------------------------
// ContributionKind
// ---------------------------------------------------------------------------

/**
 * The contribution kinds the boot planner knows: the fourteen built-in kinds,
 * plus consumer-defined kinds added by `declare module` augmentation of
 * ContributesMap. The branded `string` member admits those without widening
 * the union to plain `string`.
 */
export type ContributionKind =
	| "grants"
	| "federations"
	| "federationRedirectPolicies"
	| "tokenExchangeValidators"
	| "mfaFactors"
	| "sessionRequirements"
	| "auditHooks"
	| "routes"
	| "grantPolicyHooks"
	| "grantMiddleware"
	| "tokenBindingMechanisms"
	| "discoveryMetadata"
	| "rateLimitBudgets"
	| "federationTypes"
	| "admissionActions"
	| (string & { readonly __consumerKind?: unique symbol });

// ---------------------------------------------------------------------------
// Intermediate stage types
// ---------------------------------------------------------------------------

/**
 * A single contribution (or override) entry extracted from a module's
 * `contributes` or `overrides` map during manifest normalisation.
 */
export interface ContributionEntry {
	readonly kind: ContributionKind;
	/** Name for name-keyed kinds; instance reference for list-shaped kinds. */
	readonly key: string | symbol;
	/** Typed via per-kind contract; opaque at this layer. */
	readonly factory: unknown;
	readonly contributedBy: string;
}

/**
 * A module manifest normalised into a flat, resolved shape suitable for
 * subsequent boot planner stages.
 */
export interface NormalisedModule {
	readonly name: string;
	readonly requires: readonly ComponentKey[];
	readonly optional: readonly ComponentKey[];
	readonly providesKeys: readonly ComponentKey[];
	/**
	 * The manifest's `authoritative` as it was read, once: stage 1 refuses a
	 * value that is not a list, and names it by what it is.
	 */
	readonly authoritativeDeclared: unknown;
	/** `authoritativeDeclared`'s entries when it is a list; empty otherwise. */
	readonly authoritativeKeys: readonly ComponentKey[];
	readonly contributesEntries: readonly ContributionEntry[];
	readonly overridesEntries: readonly ContributionEntry[];
	readonly lifecycleKeys: readonly ComponentKey[];
}

/**
 * A module manifest paired with its normalised representation.
 */
export interface ValidatedModule {
	readonly manifest: Module;
	readonly normalised: NormalisedModule;
	/**
	 * The module's own configuration section, parsed by its manifest's
	 * `section.schema` at stage 1. Present exactly when the manifest
	 * declares a section — `value` is what the schema answered, which may be
	 * `undefined` for a schema that accepts an absent section — and handed to
	 * every factory of the module as `deps.section`.
	 */
	readonly section?: { readonly value: unknown };
}

/**
 * Output of stage 1 (validateManifests). Holds validated modules in input
 * order plus fast-lookup indexes.
 */
export interface ValidatedManifests {
	/** Manifests in their original input order; immutable. */
	readonly modules: readonly ValidatedModule[];
	/** Index from module name to manifest, for fast lookup in subsequent stages. */
	readonly byName: ReadonlyMap<string, ValidatedModule>;
	/** Index from `provides` key to the providing module, for fast lookup. */
	readonly providers: ReadonlyMap<ComponentKey, ValidatedModule>;
	/** Set of contribution kinds actually used by some module. */
	readonly usedKinds: ReadonlySet<ContributionKind>;
	/**
	 * The bootstrap map with `config` replaced by its parsed value (Zod
	 * defaults, transforms and stripping applied). Later stages must use this,
	 * not the raw `bootstrapComponents`, so provider factories see the parsed
	 * config.
	 */
	readonly bootstrapComponents: BootstrapMap;
	/**
	 * Each enabled `core.federations` entry whose `type` a module switched on
	 * registers, parsed by that type's schema, in the configuration's key
	 * order: what stage 4 builds a provider and a redirect policy from.
	 */
	readonly dispatchedFederations: readonly DispatchedFederation[];
}

/**
 * An enabled `core.federations` entry dispatched to the type it names, as
 * stage 1 parsed it.
 */
export interface DispatchedFederation {
	readonly type: string;
	/**
	 * The module whose declaration of the type is in force: the one that
	 * overrides it, or else the one that contributes it.
	 */
	readonly module: string;
	/**
	 * What both of the type's factories receive, frozen: the entry's name, its
	 * `callbackURL`, and the rest of it as the type's `entrySchema` answered.
	 */
	readonly instance: FederationInstance<unknown>;
}

/**
 * Per-module blueprint of dependency keys (values are resolved at
 * materialisation time).
 */
export interface DepsBlueprint {
	readonly requires: readonly ComponentKey[];
	readonly optional: readonly ComponentKey[];
}

/**
 * A single per-component activation record produced by planBoot.
 * Each entry names exactly one `(module, componentKey)` pair whose
 * factory will run during materializeComponents.
 */
export interface ProviderActivation {
	readonly module: string;
	readonly componentKey: ComponentKey;
	/**
	 * True when this entry is in the activation closure only as a seed:
	 * `lifecycle[componentKey].eager === true`, or a slot core reads. Used by
	 * diagnostics; does not change runtime behaviour.
	 */
	readonly eager: boolean;
}

/**
 * Output of stage 2 (planBoot). The intermediate representation carrying
 * validation results, topological init order, and the per-component
 * activation list.
 */
export interface BootPlan {
	readonly validated: ValidatedManifests;
	/**
	 * Module names in topological + declaration-stable order. Used as a
	 * deterministic iteration order for applyContributions and for
	 * tie-breaking inside providerActivations.
	 */
	readonly initOrder: readonly string[];
	/**
	 * Per-provider activation list in topological + declaration-stable order.
	 * This is the unit materializeComponents iterates.
	 */
	readonly providerActivations: readonly ProviderActivation[];
	/** For each module touched by the plan, the typed deps view (lookup keys, not values). */
	readonly depsBlueprint: ReadonlyMap<string, DepsBlueprint>;
}

/**
 * A per-component cleanup record captured during materializeComponents.
 * Disposed in reverse order by AppHandle.dispose().
 */
export interface CleanupRecord {
	readonly module: string;
	readonly componentKey: ComponentKey;
	readonly cleanup: (value: unknown) => void | Promise<void>;
	/** Captured component value for dispose. */
	readonly value: unknown;
}

/**
 * Output of stage 3 (materializeComponents). Holds the boot plan, the
 * materialised component map, and captured cleanup records.
 */
export interface ComponentWorld {
	readonly plan: BootPlan;
	/**
	 * Materialised component values. Typed readonly because no stage mutates
	 * the map once it is handed forward; `Object.freeze` happens only in
	 * freezeWorld.
	 */
	readonly components: Readonly<Partial<ComponentMap>>;
	/**
	 * Per-module cleanup callbacks captured during materialisation. Empty
	 * when no module declares `lifecycle[K].cleanup`. Order: insertion
	 * (forward); dispose() runs in reverse.
	 */
	readonly cleanups: readonly CleanupRecord[];
	/**
	 * Keys from the host (`bootstrapComponents` or `overrideComponents`). They
	 * are consumer-owned: `AppHandle.dispose()` must not call
	 * `Symbol.asyncDispose` on their values. Set by `materializeComponents`
	 * and passed through the later stages unchanged.
	 */
	readonly externalKeys: ReadonlySet<ComponentKey>;
}

/**
 * A route contribution collected during applyContributions, in module
 * declaration order.
 */
export interface CollectedRouteContribution {
	readonly contribution: RouteContribution;
	readonly contributedBy: string;
	/** Position in module-declaration order across all modules (0-based). */
	readonly declarationIndex: number;
}

/**
 * A route contribution with its final mount index, produced exclusively
 * inside assembleApp (stage 6) after before/after resolution.
 */
export interface OrderedRouteContribution {
	readonly contribution: RouteContribution;
	readonly contributedBy: string;
	/** Position in final mount order after before/after resolution (0-based). */
	readonly mountIndex: number;
}

/**
 * Output of stage 4 (applyContributions). Holds the component world, the
 * per-kind registries, and the collected route contributions.
 */
export interface RegistryWorld {
	readonly material: ComponentWorld;
	/** kind → registry instance */
	readonly registries: ReadonlyMap<ContributionKind, unknown>;
	/**
	 * Raw route records collected during applyContributions, in module
	 * declaration order. Mount-order computation happens in assembleApp.
	 */
	readonly routes: readonly CollectedRouteContribution[];
}

// NOTE: RegistryWorld.material.externalKeys carries the external-key set
// through to assembleApp. No separate field is needed on RegistryWorld.

/**
 * Output of stage 5 (freezeWorld). Component map and registries are now
 * structurally immutable (Object.frozen + freeze() called on each registry).
 */
export interface FrozenWorld {
	/**
	 * Materialised component map, Object.frozen. Typed as Partial because not
	 * every ComponentMap key is necessarily produced.
	 */
	readonly components: Readonly<Partial<ComponentMap>>;
	/** Each registry's freeze() called where applicable. kind → registry. */
	readonly registries: ReadonlyMap<ContributionKind, unknown>;
	/** Same shape as RegistryWorld.routes — mount-order resolution deferred to assembleApp. */
	readonly routes: readonly CollectedRouteContribution[];
	readonly cleanups: readonly CleanupRecord[];
	/**
	 * Keys from the host (`bootstrapComponents` or `overrideComponents`), which
	 * `assembleApp.buildDispose` leaves out of its `Symbol.asyncDispose`
	 * fallback: their lifecycle is the consumer's.
	 */
	readonly externalKeys: ReadonlySet<ComponentKey>;
}

// ---------------------------------------------------------------------------
// Collector contracts
// ---------------------------------------------------------------------------

/**
 * Collector for name-keyed contribution kinds (grants, federations,
 * tokenExchangeValidators, mfaFactors). Throws on duplicate register; throws
 * on unknown replace.
 */
export interface NameKeyedCollector<V> {
	readonly kind: "name-keyed";
	/** Register a value by name. Throws on duplicate. */
	register(name: string, value: V): void;
	/** Replace an existing value by name. Throws if name is unknown. */
	replace(name: string, value: V): void;
	/** Optional activation boundary — throws further mutation attempts when defined. */
	freeze?(): void;
	get(name: string): V | undefined;
	entries(): IterableIterator<readonly [string, V]>;
}

/**
 * Collector for the `grants` kind: a `NameKeyedCollector` whose values are a
 * grant handler or `null`, a grant its module's settings switched off, which
 * claims the grant type. Its mutators are function-valued properties, so
 * their parameter is checked strictly: a collector that takes handlers only
 * is not one, since boot hands it `null`.
 */
export interface GrantCollector {
	readonly kind: "name-keyed";
	/** Register a handler, or `null` for a switched-off grant, by grant type. Throws on duplicate. */
	readonly register: (name: string, value: GrantHandler | null) => void;
	/** Replace a registered grant type's value. Throws if the grant type is unknown. */
	readonly replace: (name: string, value: GrantHandler | null) => void;
	/** Optional activation boundary — throws further mutation attempts when defined. */
	readonly freeze?: () => void;
	/** The handler, `null` for a switched-off grant type, `undefined` for an unregistered one. */
	get(name: string): GrantHandler | null | undefined;
	/** The registered grant types; a switched-off one may be listed with `null`. */
	entries(): IterableIterator<readonly [string, GrantHandler | null]>;
}

/**
 * Collector for list-shaped contribution kinds (auditHooks,
 * grantPolicyHooks). Same-instance values are deduplicated.
 */
export interface ListCollector<V> {
	readonly kind: "list";
	/** Append a value. Same-instance duplicates are silently skipped. */
	append(value: V): void;
	/** Optional activation boundary. */
	freeze?(): void;
	values(): IterableIterator<V>;
}

/**
 * Collector for the routes contribution kind. Receives
 * CollectedRouteContribution (with declaration index); mount-order resolution
 * is deferred to assembleApp. freeze() is mandatory on RouteCollector.
 */
export interface RouteCollector {
	readonly kind: "list-routes";
	append(value: CollectedRouteContribution): void;
	freeze(): void;
	values(): IterableIterator<CollectedRouteContribution>;
}

/**
 * Declaration-merged map of contribution-kind collectors. Core seeds the
 * built-in kinds; consumers add custom kinds via `declare module` augmentation.
 */
export interface ContributionCollectorMap {
	/**
	 * Collector for `grants` contributions, by grant type. A `null` entry is a
	 * grant its module's settings switched off: it claims the grant type, and
	 * `grantHandlerResolver` leaves it out. It is no override target.
	 */
	readonly grants?: GrantCollector;
	/**
	 * Collector for `federations`, by name: the provider stage 4 builds for
	 * each `core.federations` entry stage 1 dispatched to its type. Boot
	 * fills it alone: a module's contribution or override, and a host
	 * collector, are refused (`contribution-kind-guarded`).
	 */
	readonly federations?: NameKeyedCollector<FederationProvider>;
	/**
	 * Collector for `federationRedirectPolicies`, by name: the redirect policy
	 * stage 4 builds beside each dispatched entry's provider, filled by boot
	 * alone like `federations`. The concrete policy type
	 * (`FederationRedirectPolicy`) is declared in the session package via
	 * `declare module` augmentation; core stores it as `unknown` to avoid a
	 * cross-package dependency.
	 */
	readonly federationRedirectPolicies?: NameKeyedCollector<unknown>;
	readonly tokenExchangeValidators?: NameKeyedCollector<ExchangeTokenValidator>;
	/**
	 * Collector for `mfaFactors` contributions. A `null` entry is a factor its
	 * configuration switched off: it claims the kind, and
	 * `mfaFactorResolver` leaves it out.
	 */
	readonly mfaFactors?: NameKeyedCollector<MfaFactor | null>;
	/**
	 * Collector for `sessionRequirements` contributions: the registered copy
	 * of each requirement, never `null`, which `sessionRequirementResolver`
	 * projects in registration order. See ADR 2026-09-28-session-admission.
	 */
	readonly sessionRequirements?: NameKeyedCollector<RegisteredRequirement>;
	/**
	 * Collector for `rateLimitBudgets` contributions, by prefix: the
	 * frozen copy of each budget, or `null` for one its module's settings
	 * switched off — which claims the prefix, and which
	 * `rateLimitBudgetResolver` leaves out.
	 */
	readonly rateLimitBudgets?: NameKeyedCollector<RateLimitSpec | null>;
	/**
	 * Collector for `federationTypes` contributions, by type: each
	 * package's declaration, its factories bound to the module's deps, which
	 * stage 4 calls for each entry stage 1 dispatched to the type.
	 */
	readonly federationTypes?: NameKeyedCollector<RegisteredFederationType>;
	/**
	 * Collector for `admissionActions` contributions, by action name: the
	 * frozen `{ name, grade }` registered from each declaration as stage 1
	 * read it, which `sessionRequirementResolver` answers through `action`.
	 */
	readonly admissionActions?: NameKeyedCollector<AdmissionAction>;
	readonly auditHooks?: ListCollector<AuditHook>;
	readonly routes?: RouteCollector;
	readonly grantPolicyHooks?: ListCollector<GrantPolicyHookContribution>;
	/**
	 * Collector for `grantMiddleware` contributions: each a `RequestHandler`,
	 * or `null` when disabled by config. Nulls are appended for value-identity
	 * dedup with sibling contributions, and `assembleApp` skips them when it
	 * mounts the middleware on the token endpoint.
	 */
	readonly grantMiddleware?: ListCollector<RequestHandler | null>;
	/**
	 * Collector for `tokenBindingMechanisms` contributions: each a
	 * `TokenBindingMechanism`, or `null` when disabled by config (skipped by
	 * `assembleApp`). Unlike `grantMiddleware`, these are raw mechanisms:
	 * `assembleApp` composes one `tokenBindingMw` over all of them so the
	 * configured `DispatchPolicy` arbitrates across modules. See ADR
	 * 2026-05-20-token-binding-first-class-abstraction.
	 */
	readonly tokenBindingMechanisms?: ListCollector<TokenBindingMechanism | null>;
	/**
	 * Collector for `discoveryMetadata` contributions. Each entry is a
	 * `OidcDiscoveryContribution` partial. `assembleApp` aggregates all entries into the
	 * single `/.well-known/openid-configuration` document via
	 * `buildDiscoveryDocument` (mounted only when an issuer is configured).
	 */
	readonly discoveryMetadata?: ListCollector<OidcDiscoveryContribution>;
}

/**
 * A `federationTypes` declaration as registered: the type's entry
 * schema, and its two factories bound to the contributing module's deps —
 * `create`, the provider's, and `redirectPolicy` — which stage 4 calls once
 * per entry dispatched to the type, with that entry's instance.
 */
export interface RegisteredFederationType {
	readonly entrySchema: z.ZodType;
	readonly create: (instance: FederationInstance<unknown>) => Contributed<FederationProvider>;
	readonly redirectPolicy: (instance: FederationInstance<unknown>) => Contributed<unknown>;
}

/**
 * The actual public input shape on createApp: every key consumers need to
 * provide a custom collector for. Built-in kinds are auto-wired by core's
 * createApp; consumers omit them.
 */
export type ContributionKindMap = Partial<ContributionCollectorMap>;

// ---------------------------------------------------------------------------
// BootstrapMap and createApp options
// ---------------------------------------------------------------------------

/**
 * What a composition root hands boot in `bootstrapComponents` beside the
 * components: inputs stage 1 reads itself. Each key is reserved — boot takes
 * it out of the map before any check reads the map and seeds no component
 * from it, and a module that provides, requires or optionally reads a
 * component of its name, or an `overrideComponents` entry of it, refuses boot
 * (`reserved-component-key`).
 */
export interface ReservedBootstrapInputs {
	/**
	 * The configuration's defaults: what the composition resolves from the
	 * `reference.conf` files of the modules it loads and core's
	 * (`moduleReferences`), in the same order, with no operator layer and no
	 * environment — unparsed, as `config` is. Optional; `undefined` is none.
	 * Resolve it exactly as the configuration is resolved — the same reader
	 * and the same conversion to plain data (`toObject` with the same
	 * options) — since a section is compared with its default whole,
	 * prototypes included, and one built differently differs.
	 *
	 * Stage 1 reads it for the top-level sections no loaded module owns that
	 * set something: one it holds and the configuration leaves equal to it —
	 * a sibling's section, which a package's `reference.conf` sets whenever
	 * any of its modules is loaded — is not named; one it holds and the
	 * operator's files or the environment set otherwise is named once at warn
	 * as `config_sections_not_loaded`; one it does not hold is
	 * `config_sections_ignored`. Without it, every such section is
	 * `config_sections_ignored`. Names only, never a value.
	 *
	 * It is read once, before any check, into a copy of its plain data: an
	 * object of sections whose values are strings, numbers, booleans, `null`,
	 * lists and objects (prototype `Object.prototype` or none), each an own
	 * data property. Anything else — not an object of sections, an accessor,
	 * a value that throws as it is read, a Proxy's trap included — refuses
	 * boot (`config-defaults-invalid`), naming the path and no value.
	 */
	readonly configDefaults?: unknown;
}

/**
 * Map of component values originating from the host environment, pre-seeded
 * into the DI graph before any module factory runs, with the reserved inputs
 * stage 1 reads itself ({@link ReservedBootstrapInputs}).
 */
export type BootstrapMap = {
	readonly [K in ComponentKey]?: ComponentMap[K];
} & ReservedBootstrapInputs;

/**
 * The minimal host contract of the built-in createApp call: a closed shape,
 * independent of ComponentMap's slot set.
 */
export type DefaultBootstrapMap = {
	readonly config: AppConfig;
	readonly pathResolver: PathResolver;
};

/**
 * Options accepted by createApp. The generic B constrains bootstrapComponents
 * to a typed subset of ComponentMap so downstream stages receive a
 * well-typed config/pathResolver.
 */
export interface CreateAppOptions<B extends BootstrapMap = DefaultBootstrapMap> {
	/** Module manifests in the order the consumer composed. */
	readonly modules: readonly Module[];

	/**
	 * Component values originating from the host environment (config,
	 * pathResolver, etc.) — pre-seeded into the DI graph before any module
	 * factory runs. A key a loaded module provides collides
	 * (`bootstrap-component-collision`), and `__proto__` as an own key — a
	 * computed key, or one JSON.parse wrote — names no component and refuses
	 * boot (`reserved-component-key`).
	 */
	readonly bootstrapComponents: B;

	/**
	 * Optional consumer-provided collectors for contribution kinds added via
	 * `declare module` augmentation of ContributesMap. Built-in kinds are
	 * auto-wired by core; consumers do NOT pass them. A type-level kind
	 * without a collector throws `unknown-contribution-kind` at
	 * validateManifests.
	 */
	readonly contributionKinds?: ContributionKindMap;

	/**
	 * Composition-root substitutions: a key here replaces the value a module's
	 * `provides[K]` would have produced, and that factory is skipped. The
	 * override's lifecycle is the consumer's.
	 *
	 * A key may not also be in `bootstrapComponents`
	 * (`bootstrap-component-collision`), nor be one a loaded module declares
	 * `authoritative` (`authoritative-component-overridden`): its readers take
	 * it as the module's own, and the module keeps deriving it from its
	 * section. With that module not loaded, the entry fills the slot as any
	 * other. `__proto__` as an own key throws `reserved-component-key`.
	 */
	readonly overrideComponents?: Partial<ComponentMap>;
}

// ---------------------------------------------------------------------------
// AppHandle
// ---------------------------------------------------------------------------

/**
 * The public handle returned by createApp. Every field is readonly, the
 * component map is frozen, and dispose is the only mutator.
 */
export interface AppHandle {
	/**
	 * Express router with all RouteContribution entries mounted in the order
	 * computed by assembleApp. Consumer code mounts this at its host
	 * server (`app.use(handle.router)`) or calls `handle.listen(port)`.
	 */
	readonly router: Router;

	/**
	 * Listen on the given port. Returns a Promise that resolves to a Server
	 * once listening. Composition roots that want their own express app may
	 * ignore this method and use `router` directly.
	 */
	listen(port: number): Promise<HttpServer>;

	/**
	 * Run cleanup callbacks in reverse-topological order against `requires`,
	 * then call Symbol.asyncDispose on values that implement it (where no
	 * `lifecycle[K].cleanup` was declared). Errors thrown during individual
	 * cleanup callbacks are aggregated; the returned Promise rejects with an
	 * AggregateError whose `errors` field contains every cleanup error.
	 * Waits for every cleanup, however long it takes: bounding it is the
	 * host's, sized by {@link AppHandle.cleanupAllowanceMs}.
	 */
	dispose(): Promise<void>;

	/**
	 * The longest `tailMs` a cleanup was registered with through
	 * `lifecycleRegistrar`, or `undefined` when none declared one: the least
	 * a host that bounds `dispose()` allows the whole of it. Tails do not add.
	 * Read when asked, so a cleanup registered after boot counts.
	 */
	readonly cleanupAllowanceMs: number | undefined;

	/**
	 * Read-only typed view of the materialised component map, Object.frozen.
	 * Typed as Partial because keys are only present when a module produced them
	 * (or they were provided via bootstrapComponents / overrideComponents).
	 */
	readonly components: Readonly<Partial<ComponentMap>>;

	/**
	 * Ordered route contributions in final mount order after before/after
	 * resolution. Populated by assembleApp (stage 6).
	 */
	readonly routes: readonly OrderedRouteContribution[];

	/**
	 * Probes registered by builders during boot, in registration order. A
	 * composition root feeds them to the readiness route
	 * (`routes/Readiness.mts`), mounted on the host app rather than inside
	 * `router` so it still answers while the auth pipeline is degraded. Empty
	 * when nothing registered a probe (a memory-only deployment).
	 */
	readonly readinessProbes: readonly ReadinessProbe[];
}

// ---------------------------------------------------------------------------
// BootStage
// ---------------------------------------------------------------------------

/**
 * The six pipeline stages of the boot planner. Used as a discriminator on
 * BootError to pinpoint which stage threw.
 */
export type BootStage =
	| "validateManifests"
	| "planBoot"
	| "materializeComponents"
	| "applyContributions"
	| "freezeWorld"
	| "assembleApp";

// ---------------------------------------------------------------------------
// BootErrorReason — 40 literals
// ---------------------------------------------------------------------------

/**
 * Every reason a BootError can carry: one literal per validation or runtime
 * failure the boot planner detects, 40 in all.
 */
export type BootErrorReason =
	| "module-factory-not-called"
	| "duplicate-module-name"
	| "duplicate-provides"
	| "bootstrap-component-collision"
	| "synthetic-key-collision"
	| "missing-required-component"
	| "unknown-contribution-kind"
	| "duplicate-contribute"
	| "override-target-missing"
	| "duplicate-override"
	| "contribute-and-override-same-key"
	| "list-shaped-override-not-allowed"
	| "lifecycle-without-provides"
	| "invalid-route-advertisement-path"
	| "config-validation-failed"
	| "circular-dependency"
	| "provides-factory-failed"
	| "contribute-factory-failed"
	| "route-order-cycle"
	| "route-order-target-missing"
	| "grant-policy-without-issuer"
	| "federation-stores-incomplete"
	| "federation-type-unhandled"
	| "discovery-document-invalid"
	| "replica-unsafe-adapter"
	| "component-absence-undeclared"
	| "session-requirement-kind-guarded"
	| "session-requirements-undeclared"
	| "session-requirement-missing"
	| "duplicate-second-factor-authority"
	| "second-factor-authority-not-declared"
	| "reserved-component-key"
	| "module-section-path-invalid"
	| "contribution-kind-guarded"
	| "contribution-malformed"
	| "config-path-relocated"
	| "environment-variable-renamed"
	| "authoritative-without-provides"
	| "authoritative-component-overridden"
	| "token-settings-lifetime-exceeds-configuration"
	| "config-defaults-invalid";

// ---------------------------------------------------------------------------
// Per-reason *Details interfaces — one per BootErrorReason, 40 in all
// ---------------------------------------------------------------------------

/**
 * A `modules` entry is a function — a module factory such as
 * `deviceGrantModule` listed without being called. `Module` requires only a
 * `name`, which every function has, so the compiler accepts it; boot would
 * otherwise take it as a manifest that contributes nothing.
 */
export interface ModuleFactoryNotCalledDetails {
	readonly reason: "module-factory-not-called";
	/** The entry's position in `modules`. */
	readonly index: number;
	/** The function's own name, or `"<anonymous>"`. */
	readonly name: string;
}

export interface DuplicateModuleNameDetails {
	readonly reason: "duplicate-module-name";
	readonly name: string;
	readonly modules: readonly [string, string];
}

export interface DuplicateProvidesDetails {
	readonly reason: "duplicate-provides";
	readonly componentKey: ComponentKey;
	readonly modules: readonly [string, string];
}

/**
 * Sub-union: `source: "module-provides"` carries the declaring module name;
 * `source: "overrideComponents"` does not (overrideComponents is
 * composition-root data, not a module).
 */
export type BootstrapComponentCollisionDetails =
	| {
			readonly reason: "bootstrap-component-collision";
			readonly componentKey: ComponentKey;
			readonly source: "module-provides";
			readonly module: string;
	  }
	| {
			readonly reason: "bootstrap-component-collision";
			readonly componentKey: ComponentKey;
			readonly source: "overrideComponents";
	  };

/**
 * A synthetic ComponentMap key (`SYNTHETIC_COMPONENT_KEYS`: the resolvers,
 * the two registrars, `deploymentMode`, `tokenBindingSettings`) appeared in
 * a module's `provides`, `bootstrapComponents` or `overrideComponents`; only
 * the boot planner produces these keys. `source: "module-provides"` carries
 * `module`; the other two sources are composition-root data and carry no
 * module name.
 */
export type SyntheticKeyCollisionDetails =
	| {
			readonly reason: "synthetic-key-collision";
			readonly componentKey: ComponentKey;
			readonly source: "module-provides";
			readonly module: string;
	  }
	| {
			readonly reason: "synthetic-key-collision";
			readonly componentKey: ComponentKey;
			readonly source: "bootstrapComponents";
	  }
	| {
			readonly reason: "synthetic-key-collision";
			readonly componentKey: ComponentKey;
			readonly source: "overrideComponents";
	  };

/**
 * The `path` chain follows the requires → provides graph from `rootModule`
 * down to the failing module.
 */
export interface MissingRequiredComponentDetails {
	readonly reason: "missing-required-component";
	readonly missingKey: ComponentKey;
	readonly rootModule: string;
	readonly path: readonly {
		readonly module: string;
		readonly requires: ComponentKey;
		readonly satisfiedBy?: string;
	}[];
}

export interface UnknownContributionKindDetails {
	readonly reason: "unknown-contribution-kind";
	readonly kind: string;
	readonly contributedBy: readonly string[];
}

/**
 * `identityKind` discriminates name-keyed collision
 * (`"name"`), route id collision (`"id"`), route mountPath collision
 * (`"mountPath"`), and effective method+path collision
 * (`"effective-method-path"`).
 */
export interface DuplicateContributeDetails {
	readonly reason: "duplicate-contribute";
	readonly kind: string;
	/**
	 * Identity string. Format depends on identityKind:
	 * - "name": the contribution name.
	 * - "id": the RouteContribution.id.
	 * - "mountPath": the RouteContribution.mountPath (no id).
	 * - "effective-method-path": "<METHOD> <mountPath><advertisement.path>".
	 */
	readonly identity: string;
	readonly identityKind: "name" | "id" | "mountPath" | "effective-method-path";
	readonly modules: readonly [string, string];
}

export interface OverrideTargetMissingDetails {
	readonly reason: "override-target-missing";
	readonly kind: string;
	readonly name: string;
	readonly overridingModule: string;
}

export interface DuplicateOverrideDetails {
	readonly reason: "duplicate-override";
	readonly kind: string;
	readonly name: string;
	readonly modules: readonly [string, string];
}

export interface ContributeAndOverrideSameKeyDetails {
	readonly reason: "contribute-and-override-same-key";
	readonly kind: string;
	readonly name: string;
	readonly module: string;
}

export interface ListShapedOverrideDetails {
	readonly reason: "list-shaped-override-not-allowed";
	readonly kind:
		| "routes"
		| "auditHooks"
		| "grantPolicyHooks"
		| "grantMiddleware"
		| "tokenBindingMechanisms"
		| "discoveryMetadata";
	readonly module: string;
}

export interface LifecycleWithoutProvidesDetails {
	readonly reason: "lifecycle-without-provides";
	readonly componentKey: ComponentKey;
	readonly module: string;
}

/**
 * A module names in `authoritative` a key it does not provide, or declares
 * `authoritative` as something other than a list. For a key,
 * `componentKey` names it — a key that is not a string described, never
 * rendered. For a value that is not a list, `declared` says what it is
 * (`the string "…"`, `null`, `the number 5`, `a Set`), and no key is named.
 */
export type AuthoritativeWithoutProvidesDetails =
	| {
			readonly reason: "authoritative-without-provides";
			readonly module: string;
			readonly componentKey: string;
	  }
	| {
			readonly reason: "authoritative-without-provides";
			readonly module: string;
			readonly declared: string;
	  };

/**
 * An `overrideComponents` entry substitutes a key a loaded module provides
 * as authoritative: settings its readers take as the module's own,
 * derived from its section, which the module's code goes on reading.
 */
export interface AuthoritativeComponentOverriddenDetails {
	readonly reason: "authoritative-component-overridden";
	readonly module: string;
	readonly componentKey: ComponentKey;
}

/**
 * An `oauthTokenSettings` names a token lifetime longer than the one core
 * resolves from the configuration, which sizes the retention of what
 * revokes that token: a host map's at stage 1, or as the value enters the
 * component map at stage 3 (a module's, or a host's that answered stage 1
 * differently).
 */
export type TokenSettingsLifetimeExceedsConfigurationDetails = {
	readonly reason: "token-settings-lifetime-exceeds-configuration";
	readonly componentKey: "oauthTokenSettings";
	/** The slot's member, as the contract names it. */
	readonly member: "accessTokenLifetime.maxExpiresIn" | "refreshTokenExpiresIn";
	/** The slot's lifetime, in seconds. */
	readonly slotSeconds: number;
	/** The lifetime core resolves from the configuration, in seconds. */
	readonly configurationSeconds: number;
} & (
	| {
			/** The host map the slot came from. */
			readonly source: "bootstrapComponents" | "overrideComponents";
	  }
	| {
			/** A module's `provides`. */
			readonly source: "provides";
			/** The module that provided it. */
			readonly module: string;
	  }
);

export interface InvalidRouteAdvertisementPathDetails {
	readonly reason: "invalid-route-advertisement-path";
	readonly module: string;
	readonly mountPath: string;
	/** The offending advertisement.path value. */
	readonly path: string;
	readonly identityKind: "missing-leading-slash";
}

/**
 * A key no component may be named where it was written:
 *
 * - `section`, required or read optionally by a module that declares its own
 *   configuration section: its deps would carry both under one name, the
 *   section shadowing the slot. Elsewhere `section` is an ordinary slot, so
 *   only this module is refused (`module`).
 * - `__proto__` as an own key of a host map (`source`): set on the component
 *   map it would replace the prototype, so every key of its value would read
 *   as a component no module provided.
 * - `configDefaults`, the reserved bootstrap input (`ReservedBootstrapInputs`),
 *   provided, required or read optionally by a module (`module`), or an
 *   `overrideComponents` entry: boot reads it itself, and no component carries it.
 */
export type ReservedComponentKeyDetails =
	| {
			readonly reason: "reserved-component-key";
			readonly componentKey: string;
			readonly source: "module-requires" | "module-optional";
			readonly module: string;
	  }
	| {
			readonly reason: "reserved-component-key";
			readonly componentKey: "configDefaults";
			readonly source: "module-provides";
			readonly module: string;
	  }
	| {
			readonly reason: "reserved-component-key";
			readonly componentKey: "configDefaults";
			readonly source: "overrideComponents";
	  }
	| {
			readonly reason: "reserved-component-key";
			/**
			 * `__proto__`, an own key of a host map: set on the component map it
			 * would replace the map's prototype, not name a component.
			 */
			readonly componentKey: "__proto__";
			readonly source: "bootstrapComponents" | "overrideComponents";
	  };

/**
 * A section path a manifest cannot have written: an `at` that is not a
 * dot-separated path of non-empty keys (or not a string), or one another
 * loaded module's section is read at too, since a section has one owner
 * (`problem` names that module); or a `relocatedFrom` that is neither a list
 * of such paths nor a map from them to paths inside the section (`""` for the
 * section itself), or whose old path is or holds a loaded module's section
 * (`problem` says what is wrong); or a `renamedVariables` entry boot cannot
 * hold (`problem` says why).
 */
export type ModuleSectionPathInvalidDetails =
	| {
			readonly reason: "module-section-path-invalid";
			readonly module: string;
			/** The `at` the manifest wrote, or the path its section is read at when that is shared. */
			readonly at: unknown;
			/** What is wrong with the path, when it is well formed but shared. */
			readonly problem?: string;
	  }
	| {
			readonly reason: "module-section-path-invalid";
			readonly module: string;
			/** The old path (a list entry or a map key), or the whole value when it is neither form. */
			readonly relocatedFrom: unknown;
			readonly problem: string;
	  }
	| {
			readonly reason: "module-section-path-invalid";
			readonly module: string;
			/** The old variable name (a map key), or the whole value when it is not a plain map. */
			readonly renamedVariable: unknown;
			readonly problem: string;
	  };

/**
 * The configuration handed to `createApp` still sets keys at paths a loaded
 * module's section moved from (`section.relocatedFrom`), found before it is
 * parsed. Each entry: the module the key moved to, the dot path the operator
 * wrote, its path now (`null` for a removed key), and the environment
 * variable bound to the new path (absent for a removed key, or where nothing
 * binds the new path yet). A bridge for the 0.x line, removed at the first
 * major release; the relocated-paths drift test fails the release that
 * forgets.
 */
export interface ConfigPathRelocatedDetails {
	readonly reason: "config-path-relocated";
	readonly relocated: readonly {
		readonly module: string;
		readonly from: string;
		/** The dot path it moved to; `null` for a key removed rather than moved. */
		readonly to: string | null;
		readonly environmentVariable?: string;
	}[];
}

/**
 * What the resolution captured of a variable a loaded module — or core, for
 * its own section — declares renamed (`section.renamedVariables`) refuses
 * boot. Each entry: the declaring module (`"core"` for core), the old name,
 * the new name and the dot path it is bound to (both `null` for a removed
 * key), and why (`state`): the new name `unset` or set to a `different`
 * string while the old one is set, a `removed` key's variable set, or a name
 * the configuration does not capture (`uncaptured`). No value is carried: a
 * variable may hold a secret. A bridge for the 0.x line, removed at the first
 * major release with `config-path-relocated`.
 */
export interface EnvironmentVariableRenamedDetails {
	readonly reason: "environment-variable-renamed";
	readonly renamed: readonly {
		readonly module: string;
		readonly from: string;
		readonly to: string | null;
		readonly path: string | null;
		readonly state: "unset" | "different" | "removed" | "uncaptured";
	}[];
}

/**
 * Thrown by either of stage 1's two parses: the composed schema over the
 * whole configuration, or, once that passed, the modules' own sections, each
 * parsed by its manifest's `section.schema`.
 */
/**
 * `bootstrapComponents.configDefaults` is not plain data boot can read once
 * (`ReservedBootstrapInputs`): `path` is the keys from its top to what is
 * wrong — `[]` for the value itself — and `problem` says what is wrong. No
 * value is carried.
 */
export interface ConfigDefaultsInvalidDetails {
	readonly reason: "config-defaults-invalid";
	readonly path: readonly string[];
	readonly problem: string;
}

export interface ConfigValidationFailedDetails {
	readonly reason: "config-validation-failed";
	/**
	 * The Zod issues from the failed parse. A section's issues are the
	 * schema's own with the section's path in front, so each `path` is the
	 * path in the configuration the operator wrote.
	 */
	readonly issues: readonly z.ZodIssue[];
	/**
	 * The composed parse: the modules whose configSchema participated, with
	 * no `schemaPath`. A section's parse: the modules whose section was
	 * refused, each with `schemaPath`, the dot-separated path its section is
	 * read at.
	 */
	readonly modules: readonly { readonly module: string; readonly schemaPath?: string }[];
}

export interface CircularDependencyDetails {
	readonly reason: "circular-dependency";
	/**
	 * Cycle as a chain: A requires X (provided by B); B requires Y (provided
	 * by C); C requires Z (provided by A). The cycle closes from the last link
	 * back to the first.
	 */
	readonly cycle: readonly {
		readonly module: string;
		readonly requires: ComponentKey;
		readonly satisfiedBy: string;
	}[];
}

/**
 * `originalError` is a typed alias of `cause`; both are set for the
 * *-factory-failed reasons. `cleanupErrors` holds the errors of the partial
 * cleanup run before the error propagates.
 */
export interface ProvidesFactoryFailedDetails {
	readonly reason: "provides-factory-failed";
	readonly module: string;
	readonly componentKey: ComponentKey;
	readonly originalError: unknown;
	readonly cleanupErrors?: readonly {
		readonly module: string;
		readonly componentKey: ComponentKey;
		readonly error: unknown;
	}[];
}

/**
 * `originalError` is a typed alias of `cause`; both are set for the
 * *-factory-failed reasons.
 */
export interface ContributeFactoryFailedDetails {
	readonly reason: "contribute-factory-failed";
	readonly module: string;
	readonly kind: string;
	readonly name: string;
	readonly originalError: unknown;
	readonly cleanupErrors?: readonly {
		readonly module: string;
		readonly componentKey: ComponentKey;
		readonly error: unknown;
	}[];
}

export interface RouteOrderCycleDetails {
	readonly reason: "route-order-cycle";
	readonly cycle: readonly {
		readonly id: string;
		readonly before?: readonly string[];
		readonly after?: readonly string[];
	}[];
}

export interface RouteOrderTargetMissingDetails {
	readonly reason: "route-order-target-missing";
	/** The referenced id that was not found. */
	readonly id: string;
	/**
	 * RouteContribution.id of the referencing route, or null when the
	 * referencing route has no `id` of its own.
	 */
	readonly referencedBy: string | null;
	/** Filled when `referencedBy` is null — the referencing route's mountPath. */
	readonly referencedByMountPath?: string;
	/** The module that contributed the referencing route — where to look. */
	readonly referencedByModule: string;
	readonly direction: "before" | "after";
}

/**
 * When any module provides `grantPolicy`, `config.oauth.jwt.issuer` must be a
 * non-empty string: the grant policy hook signs decisions against the
 * issuer, and an empty one turns its fail-closed enforcement into a silent
 * allow-all.
 */
export interface GrantPolicyWithoutIssuerDetails {
	readonly reason: "grant-policy-without-issuer";
	readonly providedBy: string;
}

/**
 * When `core.federations.<name>.enabled` is true, all six federation slots
 * must be wired: userSessionStore, sessionRPRegistry, sessionFamilyIndex,
 * sessionFederationIndex, federationTokenStore and
 * refreshTokenFamilyRevocation (matching the route-level gating in
 * `packages/oauth/src/routes.mts`).
 */
export interface FederationStoresIncompleteDetails {
	readonly reason: "federation-stores-incomplete";
	/** The federation name whose enabled flag triggered the check. */
	readonly federationName: string;
	/** The store keys that are absent from the planned component set. */
	readonly missing: readonly string[];
}

/**
 * An enabled `core.federations` entry no installed module handles: its `type`
 * is not one a module registers under `federationTypes`, the one way a
 * federation registers. Every such entry is listed, in the order written. Its routes would otherwise answer `404` while the operator
 * believes the federation is on.
 */
export interface FederationTypeUnhandledDetails {
	readonly reason: "federation-type-unhandled";
	/** Each unhandled entry: its name and the `type` it names, which no installed module registers. */
	readonly unhandled: readonly { readonly federationName: string; readonly type: string }[];
	/** The types the installed modules register, in module order. */
	readonly handled: readonly string[];
}

/**
 * The aggregated OIDC discovery document could not be formed from the
 * `discoveryMetadata` contributions (missing required field, reserved-field
 * contribution, conflicting values, empty signing algs, endpoint-in-metadata,
 * …). Wraps the underlying `DiscoveryDocumentError` (carried as `cause`) so a
 * discovery misconfiguration surfaces through the same `BootError` taxonomy as
 * every other assembleApp failure.
 */
export interface DiscoveryDocumentInvalidDetails {
	readonly reason: "discovery-document-invalid";
	/**
	 * The underlying `DiscoveryDocumentError`'s message, read by
	 * `loggableError`'s rules (`boot/failure-summary.mts`). The error itself
	 * is the BootError's `cause`.
	 */
	readonly detail: string;
}

/**
 * A composition holds state in this process's memory that a multi-replica
 * deployment must share, while `core.deployment.mode` says `"multi"`.
 * `modules` names every offending module rather than the first, so one boot
 * attempt tells the operator everything they have to change.
 */
export interface ReplicaUnsafeAdapterDetails {
	readonly reason: "replica-unsafe-adapter";
	readonly modules: readonly string[];
}

/**
 * A module attached an `AbsencePolicy` to an optional key, nothing fills the
 * slot, and the config does not carry the policy's declared-absent value: an
 * unfilled capability slot must be a stated decision, never a silent no-op.
 * Also thrown, naming the modules, when two modules attach disagreeing
 * policies to one key, so the advice does not depend on module order.
 */
export interface ComponentAbsenceUndeclaredDetails {
	readonly reason: "component-absence-undeclared";
	readonly componentKey: ComponentKey;
	/**
	 * Modules naming the key in `requires` / `optional` — the evidence that
	 * the slot is part of this app's surface (core cannot see route mounts
	 * at stage 1; reading the slot is the observable statement).
	 */
	readonly consumedBy: readonly string[];
	/** The policy's config path, dotted, as an operator writes it. */
	readonly configKey: string;
	/** The one value at `configKey` that declares the capability absent. */
	readonly absentValue: string;
}

/**
 * A host `contributionKinds` collector for a kind whose collector is the
 * planner's alone: `rateLimitBudgets` — a host collector could answer
 * a looser budget than the owning module contributed, on a prefix such as
 * RFC 8628 §5.1's device verification — `federationTypes`, and
 * `admissionActions`, whose grades admission hands the requirements,
 * `auditHooks`, which the audit fan-out reads, and `federations` and
 * `federationRedirectPolicies`, which boot fills from the dispatched
 * `core.federations` entries. Refused in `createApp`, before the kinds are
 * merged. Also, at stage 1, naming the module and the channel: a module's
 * `overrides.admissionActions` entry, naming the action (an action's grade is
 * its registrant's), and a module's `contributes` or `overrides` of
 * `federations` or `federationRedirectPolicies` whatever it holds, the module
 * switched on or not (a federation registers through its type alone), naming
 * the container's first entry only when the container is a record with one.
 */
export interface ContributionKindGuardedDetails {
	readonly reason: "contribution-kind-guarded";
	readonly kind:
		| "rateLimitBudgets"
		| "federationTypes"
		| "admissionActions"
		| "auditHooks"
		| "federations"
		| "federationRedirectPolicies";
	/** Present for a module's contribution or override; absent for a host collector. */
	readonly channel?: "contributes" | "overrides";
	readonly module?: string;
	/**
	 * The entry refused: the action of an `admissionActions` override, or the
	 * first entry of a federation kind's container when it is a record with
	 * one; absent otherwise.
	 */
	readonly name?: string;
}

/**
 * A contribution whose container, key or value its kind cannot take, found on
 * the manifest at stage 1, before any factory runs: a
 * `rateLimitBudgets`, `federationTypes` or `admissionActions` container that
 * is not a record (an array, a function, `null`) — `name` then absent — a
 * `rateLimitBudgets` prefix that is empty or holds `:` — no limiter key
 * carries it — or names an `Object.prototype` member, a `federationTypes`
 * declaration that is not an object with a Zod `entrySchema` and a
 * `factory`, or an `admissionActions` entry whose name, declaration or grade
 * registration refuses. `problem` says which.
 */
export interface ContributionMalformedDetails {
	readonly reason: "contribution-malformed";
	readonly module: string;
	readonly kind: "rateLimitBudgets" | "federationTypes" | "admissionActions";
	/** The prefix, type or action name; absent when the container itself is refused. */
	readonly name?: string;
	readonly channel: "contributes" | "overrides";
	readonly problem: string;
}

/**
 * A `sessionRequirements` entry in a module's `overrides` (stage 1), or a
 * host `contributionKinds` collector for `sessionRequirements` or
 * `mfaFactors` (`createApp`, before the kinds are merged): a requirement is
 * switched off by not installing it, and the collector the projection and
 * the boot line read is the planner's. `module` names the overriding module;
 * a host entry carries none. See ADR 2026-09-28-session-admission.
 */
export interface SessionRequirementKindGuardedDetails {
	readonly reason: "session-requirement-kind-guarded";
	readonly kind: "sessionRequirements" | "mfaFactors";
	readonly channel: "overrides" | "contributionKinds";
	readonly module?: string;
}

/**
 * `core.sessionRequirements.expected` is written and leaves out a registered
 * requirement, or is not written while a consumer of session admission is
 * installed. See ADR 2026-09-28-session-admission.
 */
export interface SessionRequirementsUndeclaredDetails {
	readonly reason: "session-requirements-undeclared";
	readonly configKey: "core.sessionRequirements.expected";
	/** What the configuration declares; `undefined` when it declares nothing. */
	readonly declared: readonly string[] | undefined;
	/** What registered, in registration order. */
	readonly registered: readonly string[];
	/** The modules that require or read `sessionRequirementResolver`; none when the key is written and nothing consults admission. */
	readonly consumedBy: readonly string[];
	readonly cleanupErrors?: readonly {
		readonly module: string;
		readonly componentKey: ComponentKey;
		readonly error: unknown;
	}[];
}

/**
 * `core.sessionRequirements.expected` names a requirement no installed module
 * registers: refused, whether or not anything consults session admission,
 * rather than left believing the requirement is in force. See ADR
 * 2026-09-28-session-admission.
 */
export interface SessionRequirementMissingDetails {
	readonly reason: "session-requirement-missing";
	readonly configKey: "core.sessionRequirements.expected";
	/** The declared names nothing registers, in declaration order. */
	readonly missing: readonly string[];
	/** What the configuration declares. */
	readonly declared: readonly string[];
	/** What registered, in registration order. */
	readonly registered: readonly string[];
	/** `core.sessionRequirements.secondFactorAuthority`, when it names one of the missing. */
	readonly secondFactorAuthority?: string;
	readonly cleanupErrors?: readonly {
		readonly module: string;
		readonly componentKey: ComponentKey;
		readonly error: unknown;
	}[];
}

/**
 * More than one registered session requirement declares the second-factor
 * authority (`SessionRequirement.secondFactorAuthority`); at most one may.
 * `requirements` names each, with its module, in registration order.
 */
export interface DuplicateSecondFactorAuthorityDetails {
	readonly reason: "duplicate-second-factor-authority";
	readonly requirements: readonly { readonly name: string; readonly module: string }[];
	readonly cleanupErrors?: readonly {
		readonly module: string;
		readonly componentKey: ComponentKey;
		readonly error: unknown;
	}[];
}

/**
 * `core.sessionRequirements.secondFactorAuthority` names a requirement that
 * fails one or more of: `core.sessionRequirements.expected` lists it
 * (`not-expected`), a module registers it (`not-registered`), and the
 * registered requirement declares the second-factor authority
 * (`not-declared`). Refused, rather than left believing the requirement the
 * composition holds to the authority enforces a second factor. `unmet` lists
 * every failed condition, in that order; `module` is the module that
 * registered it, when one did.
 */
export interface SecondFactorAuthorityNotDeclaredDetails {
	readonly reason: "second-factor-authority-not-declared";
	readonly configKey: "core.sessionRequirements.secondFactorAuthority";
	/** The requirement the key names. */
	readonly name: string;
	readonly module?: string;
	readonly unmet: readonly ("not-expected" | "not-registered" | "not-declared")[];
	readonly cleanupErrors?: readonly {
		readonly module: string;
		readonly componentKey: ComponentKey;
		readonly error: unknown;
	}[];
}

/**
 * Discriminated union (on `reason`) of the per-reason details: one member
 * per `BootErrorReason`, 40 in all.
 */
export type BootErrorDetails =
	| ModuleFactoryNotCalledDetails
	| DuplicateModuleNameDetails
	| DuplicateProvidesDetails
	| BootstrapComponentCollisionDetails
	| SyntheticKeyCollisionDetails
	| MissingRequiredComponentDetails
	| UnknownContributionKindDetails
	| DuplicateContributeDetails
	| OverrideTargetMissingDetails
	| DuplicateOverrideDetails
	| ContributeAndOverrideSameKeyDetails
	| ListShapedOverrideDetails
	| LifecycleWithoutProvidesDetails
	| InvalidRouteAdvertisementPathDetails
	| ConfigValidationFailedDetails
	| ConfigDefaultsInvalidDetails
	| CircularDependencyDetails
	| ProvidesFactoryFailedDetails
	| ContributeFactoryFailedDetails
	| RouteOrderCycleDetails
	| RouteOrderTargetMissingDetails
	| GrantPolicyWithoutIssuerDetails
	| FederationStoresIncompleteDetails
	| FederationTypeUnhandledDetails
	| DiscoveryDocumentInvalidDetails
	| ReplicaUnsafeAdapterDetails
	| ComponentAbsenceUndeclaredDetails
	| SessionRequirementKindGuardedDetails
	| SessionRequirementsUndeclaredDetails
	| SessionRequirementMissingDetails
	| DuplicateSecondFactorAuthorityDetails
	| SecondFactorAuthorityNotDeclaredDetails
	| ReservedComponentKeyDetails
	| ModuleSectionPathInvalidDetails
	| ContributionKindGuardedDetails
	| ContributionMalformedDetails
	| ConfigPathRelocatedDetails
	| EnvironmentVariableRenamedDetails
	| AuthoritativeWithoutProvidesDetails
	| AuthoritativeComponentOverriddenDetails
	| TokenSettingsLifetimeExceedsConfigurationDetails;

// ---------------------------------------------------------------------------
// BootError class
// ---------------------------------------------------------------------------

/**
 * The boot planner's single error class: every boot-time failure is a
 * BootError with a discriminated `reason`, the `stage` that threw, and a
 * structured `details` payload. `cause` is kept verbatim for the
 * *-factory-failed reasons; printed, it is projected (`util.inspect.custom`).
 */
export class BootError extends Error {
	readonly reason: BootErrorReason;
	readonly stage: BootStage;
	readonly details: BootErrorDetails;

	constructor(args: {
		message: string;
		reason: BootErrorReason;
		stage: BootStage;
		details: BootErrorDetails;
		cause?: unknown;
	}) {
		// Pass `cause` only when defined: `super(message, { cause: undefined })`
		// would create an own `cause` property holding `undefined`, and `cause`
		// is present only for the reasons that carry one.
		super(args.message, args.cause !== undefined ? { cause: args.cause } : undefined);
		this.name = "BootError";
		this.reason = args.reason;
		this.stage = args.stage;
		this.details = args.details;
	}

	/**
	 * How a boot failure prints (Node's unhandled-rejection printer,
	 * `console.error`, `util.inspect`): name, message, stack frames, `reason`,
	 * `stage` and `details`, with every error it carries (`cause`,
	 * `details.originalError`, each `details.cleanupErrors[].error`) shown as
	 * its `loggableError` projection. Printed whole, they would write what a
	 * parser quoted, a Redis reply's arguments or a thrown string to the log.
	 * The errors themselves stay on the object for callers that read them.
	 */
	[inspect.custom](_depth: number, options: InspectOptions, print: typeof inspect): string {
		const details = (this.details ?? {}) as unknown as Record<string, unknown>;
		const cleanupErrors = details.cleanupErrors;
		const shown = {
			reason: this.reason,
			stage: this.stage,
			details: {
				...details,
				...("originalError" in details
					? { originalError: loggableError(details.originalError) }
					: {}),
				...(Array.isArray(cleanupErrors)
					? {
							cleanupErrors: cleanupErrors.map((entry: Record<string, unknown>) => ({
								...entry,
								error: loggableError(entry.error),
							})),
						}
					: {}),
			},
			...(this.cause !== undefined ? { cause: loggableError(this.cause) } : {}),
		};
		const frames =
			typeof this.stack === "string"
				? this.stack
						.split("\n")
						.filter((line) => /^ {4}at /.test(line))
						.join("\n")
				: "";
		return `${this.name}: ${this.message}${frames === "" ? "" : `\n${frames}`} ${print(shown, options)}`;
	}
}

// ---------------------------------------------------------------------------
// Final re-export
// ---------------------------------------------------------------------------

/**
 * Re-export HttpMethod so consumers don't need a second import for the HTTP
 * method literal union.
 */
export type { HttpMethod };
