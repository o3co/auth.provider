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
 * boot/types.mts — single file carrying every type the boot planner stages
 * share, plus the BootError class catalogue.
 *
 * A single file (not per-stage files) because the discriminated
 * BootError.details union has 23 variants and the intermediate stage types
 * form a tight chain — splitting would force unavoidable circular imports
 * between later stage modules.
 *
 * Per A2-β §3.2 (intermediate types), §6.1 (BootError + reasons + per-reason
 * details), §6.2 (createApp options + collector contracts), §6.3 (AppHandle).
 */

import type { Server as HttpServer } from "node:http";
import type { Router } from "express";
import type { z } from "zod";
import type { AppConfig } from "../config/application.schema.mjs";
import type { ComponentKey, ComponentMap } from "../modules/manifest/component-map.mjs";
import type {
	AuditHook,
	ExchangeTokenValidator,
	FederationProvider,
	GrantHandler,
	GrantPolicyHook,
	MfaFactor,
} from "../modules/manifest/contributes-map.mjs";
import type { Module } from "../modules/manifest/module-spec.mjs";
import type { HttpMethod, RouteContribution } from "../modules/manifest/route-contribution.mjs";
import type { PathResolver } from "../modules/types.mjs";

// ---------------------------------------------------------------------------
// ComponentMap bootstrap slots (per A2-β §6.2 DefaultBootstrapMap contract)
// ---------------------------------------------------------------------------
//
// `config` and `pathResolver` are the two slots every createApp call MUST
// receive from the host environment per spec §6.2's DefaultBootstrapMap
// shape. They are declaration-merged into ComponentMap here (in the boot
// package, where they originate) so that DefaultBootstrapMap satisfies
// `B extends BootstrapMap` and so modules can declare them in `requires`.
//
// Per A2-α §6.1 the v0.5.0 baseline slot set lands incrementally during
// Phases 3-8; these two are owned by Phase 4 / A2-β because they are
// the boot-planner-imposed contract, not protocol features.
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly config: AppConfig;
		readonly pathResolver: PathResolver;
	}
}

// ---------------------------------------------------------------------------
// ContributionKind
// ---------------------------------------------------------------------------

/**
 * The set of contribution kinds used internally by the boot planner.
 * Built-in kinds are the eight listed (the 7 v0.5.0 originals + A5's
 * `federationRedirectPolicies`); the structural escape
 * `(string & { readonly __consumerKind?: unique symbol })` admits
 * consumer-defined kinds added via `declare module` augmentation of
 * ContributesMap without widening to plain `string`.
 *
 * Per A2-β §3.2 + A5 §6.
 */
export type ContributionKind =
	| "grants"
	| "federations"
	| "federationRedirectPolicies"
	| "tokenExchangeValidators"
	| "mfaFactors"
	| "auditHooks"
	| "routes"
	| "grantPolicyHooks"
	| (string & { readonly __consumerKind?: unique symbol });

// ---------------------------------------------------------------------------
// Intermediate stage types — Per A2-β §3.2
// ---------------------------------------------------------------------------

/**
 * A single contribution (or override) entry extracted from a module's
 * `contributes` or `overrides` map during manifest normalisation.
 *
 * Per A2-β §3.2.
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
 *
 * Per A2-β §3.2.
 */
export interface NormalisedModule {
	readonly name: string;
	readonly requires: readonly ComponentKey[];
	readonly optional: readonly ComponentKey[];
	readonly providesKeys: readonly ComponentKey[];
	readonly contributesEntries: readonly ContributionEntry[];
	readonly overridesEntries: readonly ContributionEntry[];
	readonly lifecycleKeys: readonly ComponentKey[];
}

/**
 * A module manifest paired with its normalised representation.
 *
 * Per A2-β §3.2.
 */
export interface ValidatedModule {
	readonly manifest: Module;
	readonly normalised: NormalisedModule;
}

/**
 * Output of stage 1 (validateManifests). Holds validated modules in input
 * order plus fast-lookup indexes.
 *
 * Per A2-β §3.2.
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
	 * The bootstrap map with `config` replaced by the parsed (Zod-validated)
	 * value. Zod defaults, transforms, and stripping are applied. All downstream
	 * stages (planBoot, materializeComponents, applyContributions) must use this
	 * field instead of the raw `bootstrapComponents` passed to `createApp` so
	 * that Zod defaults / transforms reach provider factories.
	 *
	 * Per A2-β §5.1 step 13.
	 */
	readonly bootstrapComponents: BootstrapMap;
}

/**
 * Per-module blueprint of dependency keys (values are resolved at
 * materialisation time). Per A2-β §3.2.
 */
export interface DepsBlueprint {
	readonly requires: readonly ComponentKey[];
	readonly optional: readonly ComponentKey[];
}

/**
 * A single per-component activation record produced by planBoot.
 * Each entry names exactly one `(module, componentKey)` pair whose
 * factory will run during materializeComponents.
 *
 * Per A2-β §3.2.
 */
export interface ProviderActivation {
	readonly module: string;
	readonly componentKey: ComponentKey;
	/**
	 * True when this entry is in the activation closure only because
	 * `lifecycle[componentKey].eager === true`. Used by diagnostics; does not
	 * change runtime behaviour.
	 */
	readonly eager: boolean;
}

/**
 * Output of stage 2 (planBoot). The intermediate representation carrying
 * validation results, topological init order, and the per-component
 * activation list.
 *
 * Per A2-β §3.2.
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
 *
 * Per A2-β §3.2.
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
 *
 * Per A2-β §3.2.
 */
export interface ComponentWorld {
	readonly plan: BootPlan;
	/**
	 * Materialised component values. The TYPE is `Readonly<Partial<...>>` —
	 * the planner-internal contract is that no stage code mutates this map
	 * once it is handed forward. RUNTIME Object.freeze does NOT happen until
	 * freezeWorld; the type-level readonly is enforced at the stage boundary.
	 */
	readonly components: Readonly<Partial<ComponentMap>>;
	/**
	 * Per-module cleanup callbacks captured during materialisation. Empty
	 * when no module declares `lifecycle[K].cleanup`. Order: insertion
	 * (forward); dispose() runs in reverse.
	 */
	readonly cleanups: readonly CleanupRecord[];
	/**
	 * The set of component keys that originated from the host environment
	 * (`bootstrapComponents` or `overrideComponents`). These keys are
	 * consumer-owned: the boot planner must NOT call `Symbol.asyncDispose` on
	 * their values in `AppHandle.dispose()`. Populated by
	 * `materializeComponents`; threaded through subsequent stages unchanged.
	 *
	 * Per A2-β §5.3 (consumer-owned lifecycle) / §8.1 (dispose fallback
	 * exclusion).
	 */
	readonly externalKeys: ReadonlySet<ComponentKey>;
}

/**
 * A route contribution collected during applyContributions, in module
 * declaration order.
 *
 * Per A2-β §3.2.
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
 *
 * Per A2-β §3.2.
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
 *
 * Per A2-β §3.2.
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
 *
 * Per A2-β §3.2.
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
	 * The set of component keys that originated from the host environment
	 * (`bootstrapComponents` or `overrideComponents`). `assembleApp.buildDispose`
	 * excludes these keys from the `Symbol.asyncDispose` fallback loop because
	 * their lifecycle is the consumer's responsibility.
	 *
	 * Per A2-β §5.3 / §8.1.
	 */
	readonly externalKeys: ReadonlySet<ComponentKey>;
}

// ---------------------------------------------------------------------------
// Collector contracts — Per A2-β §6.2
// ---------------------------------------------------------------------------

/**
 * Collector for name-keyed contribution kinds (grants, federations,
 * tokenExchangeValidators, mfaFactors). Throws on duplicate register; throws
 * on unknown replace.
 *
 * Per A2-β §6.2.
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
 * Collector for list-shaped contribution kinds (auditHooks,
 * grantPolicyHooks). Same-instance deduplication per A2-α §4.5.
 *
 * Per A2-β §6.2.
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
 *
 * Per A2-β §6.2.
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
 *
 * Per A2-β §6.2.
 */
export interface ContributionCollectorMap {
	readonly grants?: NameKeyedCollector<GrantHandler>;
	readonly federations?: NameKeyedCollector<FederationProvider>;
	/**
	 * Collector for `federationRedirectPolicies` contributions.
	 * The concrete policy type (`FederationRedirectPolicy`) is declared in the
	 * session package via `declare module` augmentation; core stores it as
	 * `unknown` to avoid a cross-package dependency.
	 * Per A5 §8.1.
	 */
	readonly federationRedirectPolicies?: NameKeyedCollector<unknown>;
	readonly tokenExchangeValidators?: NameKeyedCollector<ExchangeTokenValidator>;
	readonly mfaFactors?: NameKeyedCollector<MfaFactor>;
	readonly auditHooks?: ListCollector<AuditHook>;
	readonly routes?: RouteCollector;
	readonly grantPolicyHooks?: ListCollector<GrantPolicyHook>;
}

/**
 * The actual public input shape on createApp: every key consumers need to
 * provide a custom collector for. Built-in kinds are auto-wired by core's
 * createApp; consumers omit them.
 *
 * Per A2-β §6.2.
 */
export type ContributionKindMap = Partial<ContributionCollectorMap>;

// ---------------------------------------------------------------------------
// BootstrapMap and createApp options — Per A2-β §6.2
// ---------------------------------------------------------------------------

/**
 * Map of component values originating from the host environment, pre-seeded
 * into the DI graph before any module factory runs.
 *
 * Per A2-β §6.2.
 */
export type BootstrapMap = {
	readonly [K in ComponentKey]?: ComponentMap[K];
};

/**
 * Default bootstrap map shape. The minimal host-environment contract for the
 * built-in createApp call. Closed shape per spec §6.2: independent of
 * ComponentMap's slot set — defines what createApp requires from the host
 * environment by default.
 *
 * Per A2-β §6.2.
 */
export type DefaultBootstrapMap = {
	readonly config: AppConfig;
	readonly pathResolver: PathResolver;
};

/**
 * Options accepted by createApp. The generic B constrains bootstrapComponents
 * to a typed subset of ComponentMap so downstream stages receive a
 * well-typed config/pathResolver.
 *
 * Per A2-β §6.2.
 */
export interface CreateAppOptions<B extends BootstrapMap = DefaultBootstrapMap> {
	/** Module manifests in the order the consumer composed. */
	readonly modules: readonly Module[];

	/**
	 * Component values originating from the host environment (config,
	 * pathResolver, etc.) — pre-seeded into the DI graph before any module
	 * factory runs.
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
	 * Optional composition-root substitutions for components. Keys present here
	 * REPLACE the value a module's `provides[K]` would have produced. The
	 * would-be provider factory is skipped. The override value's lifecycle is
	 * the consumer's responsibility.
	 *
	 * Mutually exclusive with `bootstrapComponents` for the same key (collision
	 * throws `bootstrap-component-collision` at validateManifests).
	 */
	readonly overrideComponents?: Partial<ComponentMap>;
}

// ---------------------------------------------------------------------------
// AppHandle — Per A2-β §6.3
// ---------------------------------------------------------------------------

/**
 * The public handle returned by createApp. Theme D: every field is readonly;
 * the component map is frozen; dispose is the only mutator.
 *
 * Per A2-β §6.3.
 */
export interface AppHandle {
	/**
	 * Express router with all RouteContribution entries mounted in the order
	 * computed by assembleApp §5.6. Consumer code mounts this at its host
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
	 */
	dispose(): Promise<void>;

	/**
	 * Read-only typed view of the materialised component map, Object.frozen.
	 * Typed as Partial because keys are only present when a module produced them
	 * (or they were provided via bootstrapComponents / overrideComponents).
	 */
	readonly components: Readonly<Partial<ComponentMap>>;

	/**
	 * Ordered route contributions in final mount order after before/after
	 * resolution. Populated by assembleApp (stage 6). Per A2-β §6.3 / A2-γ §7.2.
	 */
	readonly routes: readonly OrderedRouteContribution[];
}

// ---------------------------------------------------------------------------
// BootStage — Per A2-β §6.1
// ---------------------------------------------------------------------------

/**
 * The six pipeline stages of the boot planner. Used as a discriminator on
 * BootError to pinpoint which stage threw.
 *
 * Per A2-β §6.1.
 */
export type BootStage =
	| "validateManifests"
	| "planBoot"
	| "materializeComponents"
	| "applyContributions"
	| "freezeWorld"
	| "assembleApp";

// ---------------------------------------------------------------------------
// BootErrorReason — exactly 23 literals, Per A2-β §6.1
// ---------------------------------------------------------------------------

/**
 * All possible reasons a BootError can be thrown. Each literal corresponds to
 * one validation or runtime failure the boot planner can detect. There are
 * exactly 23 reasons.
 *
 * Per A2-β §6.1. Extended by issue #101 (mfa-partial-wiring,
 * federation-stores-incomplete).
 */
export type BootErrorReason =
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
	| "federation-redirect-policy-unpaired"
	| "grant-policy-without-issuer"
	| "mfa-partial-wiring"
	| "federation-stores-incomplete";

// ---------------------------------------------------------------------------
// Per-reason *Details interfaces — 23 total, Per A2-β §6.1
// ---------------------------------------------------------------------------

/** Per A2-β §6.1. */
export interface DuplicateModuleNameDetails {
	readonly reason: "duplicate-module-name";
	readonly name: string;
	readonly modules: readonly [string, string];
}

/** Per A2-β §6.1. */
export interface DuplicateProvidesDetails {
	readonly reason: "duplicate-provides";
	readonly componentKey: ComponentKey;
	readonly modules: readonly [string, string];
}

/**
 * Sub-union: `source: "module-provides"` carries the declaring module name;
 * `source: "overrideComponents"` does not (overrideComponents is
 * composition-root data, not a module).
 *
 * Per A2-β §6.1.
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
 * A synthetic ComponentMap key (federationProviders, tokenExchangeValidatorResolver,
 * grantHandlerResolver) appeared in a module's `provides`, in
 * `bootstrapComponents`, or in `overrideComponents`. Per A2-α §6.5 these keys
 * are produced exclusively by prepareSyntheticProjections (§5.4 step 0).
 *
 * Sub-union: `source: "module-provides"` carries `module`; the other two
 * sources are composition-root data and carry no module name.
 *
 * Per A2-β §6.1.
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
 * Per A2-β §6.1. The `path` chain follows the requires → provides graph from
 * `rootModule` down to the failing module. See §5.1 step 4 for the
 * normative path-construction algorithm.
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

/** Per A2-β §6.1. */
export interface UnknownContributionKindDetails {
	readonly reason: "unknown-contribution-kind";
	readonly kind: string;
	readonly contributedBy: readonly string[];
}

/**
 * Per A2-β §6.1. `identityKind` discriminates name-keyed collision
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

/** Per A2-β §6.1. */
export interface OverrideTargetMissingDetails {
	readonly reason: "override-target-missing";
	readonly kind: string;
	readonly name: string;
	readonly overridingModule: string;
}

/** Per A2-β §6.1. */
export interface DuplicateOverrideDetails {
	readonly reason: "duplicate-override";
	readonly kind: string;
	readonly name: string;
	readonly modules: readonly [string, string];
}

/** Per A2-β §6.1. */
export interface ContributeAndOverrideSameKeyDetails {
	readonly reason: "contribute-and-override-same-key";
	readonly kind: string;
	readonly name: string;
	readonly module: string;
}

/** Per A2-β §6.1. */
export interface ListShapedOverrideDetails {
	readonly reason: "list-shaped-override-not-allowed";
	readonly kind: "routes" | "auditHooks" | "grantPolicyHooks";
	readonly module: string;
}

/** Per A2-β §6.1. */
export interface LifecycleWithoutProvidesDetails {
	readonly reason: "lifecycle-without-provides";
	readonly componentKey: ComponentKey;
	readonly module: string;
}

/** Per A2-β §6.1. */
export interface InvalidRouteAdvertisementPathDetails {
	readonly reason: "invalid-route-advertisement-path";
	readonly module: string;
	readonly mountPath: string;
	/** The offending advertisement.path value. */
	readonly path: string;
	readonly identityKind: "missing-leading-slash";
}

/** Per A2-β §6.1. */
export interface ConfigValidationFailedDetails {
	readonly reason: "config-validation-failed";
	/** Verbatim Zod issues from the failed parse. */
	readonly issues: readonly z.ZodIssue[];
	/** Modules whose configSchema participated in the composed schema. */
	readonly modules: readonly { readonly module: string; readonly schemaPath?: string }[];
}

/** Per A2-β §6.1. */
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
 * Per A2-β §6.1. `originalError` is a typed alias of `cause`; both are
 * populated for *-factory-failed reasons (Codex Session 03 verdict C3).
 * `cleanupErrors` captures any errors thrown by partial-cleanup callbacks
 * run before the error propagates.
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
 * Per A2-β §6.1. `originalError` is a typed alias of `cause`; both are
 * populated for *-factory-failed reasons (Codex Session 03 verdict C3).
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

/** Per A2-β §6.1. */
export interface RouteOrderCycleDetails {
	readonly reason: "route-order-cycle";
	readonly cycle: readonly {
		readonly id: string;
		readonly before?: readonly string[];
		readonly after?: readonly string[];
	}[];
}

/** Per A2-β §6.1. */
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
	readonly direction: "before" | "after";
}

/**
 * A federation contributing `federations[name]` lacks a matching
 * `federationRedirectPolicies[name]` (or vice versa).
 *
 * `name`: the unmatched federation/policy key.
 * `side`: which side is missing its pair.
 * `contributedBy`: the module that contributed the unpaired side.
 *
 * Per A5 §8.2.
 */
export interface FederationRedirectPolicyUnpairedDetails {
	readonly reason: "federation-redirect-policy-unpaired";
	readonly name: string;
	readonly side: "federation-without-policy" | "policy-without-federation";
	readonly contributedBy: string;
}

/**
 * CP-20 invariant restoring the v0.4.x guard: when any module provides
 * `grantPolicy`, `config.oauth.jwt.issuer` must be a non-empty string.
 * The grant policy hook signs decisions against the configured issuer; an
 * empty issuer turns CP-18 fail-closed enforcement into silent allow-all.
 *
 * Phase 9 dropped the v0.4.x A4 four-store invariant: in v0.5.0 the four
 * user-session slots are split across packages (sessionModule consumes 2,
 * oauthModule consumes 2). Step 4 (checkRequiresClosure) already enforces
 * the per-module wiring contract, so a separate "all-or-none" check would
 * mis-fire on legitimate test fixtures that exercise only one subsystem.
 */
export interface GrantPolicyWithoutIssuerDetails {
	readonly reason: "grant-policy-without-issuer";
	readonly providedBy: string;
}

/** Per A2-β §6.1 amendment 2026-05 (issue #101). */
export interface MfaPartialWiringDetails {
	readonly reason: "mfa-partial-wiring";
	readonly missing: readonly ("mfaProviderFactory" | "mfaTransactionStore")[];
}

/**
 * Per A2-β §6.1 amendment 2026-05 (issue #101 TODO-F-1).
 * When config.federations.<name>.enabled is true, all 5 session/federation
 * stores must be wired: userSessionStore, sessionRPRegistry,
 * sessionFamilyIndex, sessionFederationIndex, and federationTokenStore.
 */
export interface FederationStoresIncompleteDetails {
	readonly reason: "federation-stores-incomplete";
	/** The federation name whose enabled flag triggered the check. */
	readonly federationName: string;
	/** The store keys that are absent from the planned component set. */
	readonly missing: readonly string[];
}

/**
 * Discriminated union of all per-reason Details interfaces.
 * The `reason` field on each member is the discriminant.
 *
 * Per A2-β §6.1, extended by A5 §8.2 and the Phase 9 boot-validator
 * restoration (A4 four-store + CP-20 issuer guard). Extended by issue #101
 * (mfa-partial-wiring, federation-stores-incomplete).
 */
export type BootErrorDetails =
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
	| CircularDependencyDetails
	| ProvidesFactoryFailedDetails
	| ContributeFactoryFailedDetails
	| RouteOrderCycleDetails
	| RouteOrderTargetMissingDetails
	| FederationRedirectPolicyUnpairedDetails
	| GrantPolicyWithoutIssuerDetails
	| MfaPartialWiringDetails
	| FederationStoresIncompleteDetails;

// ---------------------------------------------------------------------------
// BootError class — Per A2-β §6.1
// ---------------------------------------------------------------------------

/**
 * The single error class for the boot planner's scope. Every boot-time
 * failure surfaces as a BootError with a structured `details` payload and
 * a discriminated `reason` field.
 *
 * Codex Session 03 verdict: single class, discriminated reason, stage field.
 * `cause` is preserved verbatim for *-factory-failed reasons (verdict C3).
 *
 * Per A2-β §6.1.
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
		// Pass `cause` to super only when defined. Calling
		// `super(message, { cause: undefined })` materialises an own `cause`
		// property with value `undefined`, breaking the spec §6.1 contract that
		// cause is populated only for *-factory-failed reasons.
		super(args.message, args.cause !== undefined ? { cause: args.cause } : undefined);
		this.name = "BootError";
		this.reason = args.reason;
		this.stage = args.stage;
		this.details = args.details;
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
