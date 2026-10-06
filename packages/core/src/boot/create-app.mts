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
 * boot/create-app.mts: the boot planner's orchestrator. Wires stages 1-6
 * (`validateManifests → planBoot → materializeComponents →
 * applyContributions → freezeWorld → assembleApp`) into one async `createApp`
 * that holds no per-call state. `mergeWithBuiltins` seeds the built-in
 * contribution kinds; consumer-supplied kinds overlay them.
 */

import type { RequestHandler, Router } from "express";
import { createLifecycleRegistrar } from "../adapters/AdapterFactory.mjs";
import type { OidcDiscoveryContribution } from "../discovery/types.mjs";
import { GrantRegistry } from "../grants/registry.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { TokenBindingMechanism } from "../middleware/tokenBinding.mjs";
import type {
	AuditHook,
	ExchangeTokenValidator,
	FederationProvider,
	GrantHandler,
	GrantPolicyHookContribution,
	MfaFactor,
} from "../modules/manifest/contributes-map.mjs";
import type { RateLimitSpec } from "../ratelimit/types.mjs";
import { createReadinessRegistrar } from "../readiness/registrar.mjs";
import type { AdmissionAction } from "../session-admission/actions.mjs";
import type { RegisteredRequirement } from "../session-admission/requirement.mjs";
import type { SessionCloseNotifier } from "../session-lifecycle/notifier.mjs";
import { applyContributions } from "./apply-contributions.mjs";
import { assembleApp } from "./assemble-app.mjs";
import { freezeWorld } from "./freeze-world.mjs";
import { materializeComponents } from "./materialize-components.mjs";
import { planBoot } from "./plan-boot.mjs";
import { runCleanupsReverse } from "./run-cleanups.mjs";
import type {
	AppHandle,
	BootstrapMap,
	CleanupRecord,
	CollectedRouteContribution,
	ContributionCollectorMap,
	ContributionKindMap,
	CreateAppOptions,
	DefaultBootstrapMap,
	GrantCollector,
	ListCollector,
	NameKeyedCollector,
	RegisteredFederationType,
	RouteCollector,
} from "./types.mjs";
import { refuseGuardedHostKinds, validateManifests } from "./validate-manifests.mjs";

// ---------------------------------------------------------------------------
// Public API — createApp
// ---------------------------------------------------------------------------

/**
 * Orchestrator for the boot planner.
 *
 * Stages:
 *   1. validateManifests — normalise + validate all manifests.
 *   2. planBoot — build dependency graph, detect cycles, compute init order.
 *   3. materializeComponents — run provider factories in topological order.
 *   4. applyContributions — route contributions to collectors.
 *   5. freezeWorld — Object.freeze component map + call freeze() on registries.
 *   6. assembleApp — mount routes, build AppHandle.
 *
 * A refused boot rolls back what stage 3 opened: stages 3 and 4 run the
 * lifecycle cleanups recorded so far, in reverse, before they throw, and a
 * failure at stage 5 or 6 runs them here; then the `LifecycleRegistrar`
 * drains. Each cleanup runs once.
 *
 * `mergeWithBuiltins` seeds the built-in contribution kinds and consumer kinds
 * overlay them, except `sessionRequirements` and `mfaFactors`
 * (`session-requirement-kind-guarded`) and `rateLimitBudgets`,
 * `federationTypes`, `admissionActions`, `sessionCloseNotifiers`, `auditHooks`, `federations` and
 * `federationRedirectPolicies` (`contribution-kind-guarded`), which
 * `createApp` refuses to see replaced before the merge
 * (`refuseGuardedHostKinds`).
 *
 * The generic `B` constrains `bootstrapComponents` to a typed subset of
 * `ComponentMap` so downstream stages receive a well-typed config/pathResolver.
 */
export async function createApp<B extends BootstrapMap = DefaultBootstrapMap>(
	options: CreateAppOptions<B>,
): Promise<AppHandle> {
	const { modules } = options;
	// Each host map is read once, here: stage 1 checks what later stages use,
	// so a map that answers differently on a later read (a Proxy, a getter)
	// cannot have one answer checked and another materialised — nor can the
	// collectors the guard below reads differ from the ones merged.
	const bootstrapComponents = snapshotHostMap(options.bootstrapComponents);
	const overrideComponents = snapshotHostMap(options.overrideComponents);
	const contributionKinds = snapshotHostMap(options.contributionKinds);

	// A host collector for a guarded kind is refused before anything is merged
	// or validated.
	refuseGuardedHostKinds(contributionKinds);

	// Merge consumer kinds on top of built-in defaults.
	const merged = mergeWithBuiltins(contributionKinds);

	// Stage 1: validateManifests. validated.bootstrapComponents carries the
	// parsed config (Zod defaults / transforms applied); every later stage must
	// use it instead of the raw bootstrapComponents.
	const validated = validateManifests({
		modules,
		bootstrapComponents,
		contributionKinds: merged,
		overrideComponents,
	});
	const validatedBootstrap = validated.bootstrapComponents;

	// Pre-seed the lifecycle registrar as a bootstrap component so modules
	// that declare `optional: ["lifecycleRegistrar"]` can forward it into
	// `createAdapterFactory(kind, { lifecycle: ... })`. Owned by the boot
	// planner: validateManifests refuses a consumer override
	// (`bootstrap-component-collision`).
	const lifecycleReg = createLifecycleRegistrar();
	// Same pre-seeding for readiness: a builder that opens a connection is the
	// only place that can probe it, so it needs the registrar at build time.
	const readinessReg = createReadinessRegistrar();
	const bootstrapWithLifecycle = {
		...validatedBootstrap,
		lifecycleRegistrar: lifecycleReg,
		readinessRegistrar: readinessReg,
	} as typeof validatedBootstrap;

	// The stage-3 lifecycle cleanups this function runs when a later stage
	// fails: set once stage 4 has returned, since stages 3 and 4 run their own
	// before they throw.
	let unreleased: readonly CleanupRecord[] = [];
	try {
		// Stage 2: planBoot.
		const plan = planBoot(validated, bootstrapWithLifecycle, overrideComponents);

		// Stage 3: materializeComponents.
		const material = await materializeComponents(
			plan,
			bootstrapWithLifecycle,
			overrideComponents,
			merged,
		);

		// Stage 4: applyContributions.
		const registry = await applyContributions(material, merged);
		unreleased = material.cleanups;

		// Stage 5: freezeWorld.
		const frozen = freezeWorld(registry);

		// assembleApp is synchronous but needs express.Router, so the async
		// orchestrator imports express and passes it via options.express.
		let expressMod: { Router: () => Router } | undefined;
		try {
			expressMod = (await import("express")) as { Router: () => Router };
		} catch {
			// express is an optional peer dep; assembleApp will fall back to
			// createRequire if not resolvable via dynamic import.
			expressMod = undefined;
		}

		// Stage 6: assembleApp.
		return assembleApp(frozen, { express: expressMod, lifecycleReg, readinessReg });
	} catch (err) {
		// A refusal at stage 5 or 6 carries no `cleanupErrors`, so a cleanup
		// that throws here is not reported, as at stage 3's refusals of that
		// kind; the error that failed boot is rethrown.
		await runCleanupsReverse(unreleased);
		// Partial-boot failure: a builder may already have registered a
		// cleanup, so drain best-effort to avoid leaking adapter sub-resources.
		// There is no AppHandle; a failed cleanup is logged through the logger
		// the composition handed in (bootstrap component or override, never
		// both), else through `consoleLogger`.
		await lifecycleReg._drain(
			overrideComponents?.logger ?? validatedBootstrap.logger ?? consoleLogger,
			"boot_failure",
		);
		throw err;
	}
}

// ---------------------------------------------------------------------------
// Internal: snapshotHostMap
// ---------------------------------------------------------------------------

/**
 * A plain copy of a host map's own enumerable keys and their values, each
 * read once. Every key is defined, not assigned, so an own `__proto__` stays a
 * key (stage 1 refuses it, naming the map) rather than becoming the copy's
 * prototype. Anything that is not an object is handed on as it is, for stage
 * 1 to judge.
 */
function snapshotHostMap<T>(map: T): T {
	if (map === null || typeof map !== "object") return map;
	const copy: Record<string, unknown> = {};
	const source = map as Record<string, unknown>;
	for (const key of Object.keys(source)) {
		Object.defineProperty(copy, key, {
			// Stage 1 refuses an own `__proto__` whatever it holds, so its value
			// is never read: an accessor there does not run.
			value: key === "__proto__" ? undefined : source[key],
			enumerable: true,
			writable: true,
			configurable: true,
		});
	}
	return copy as T;
}

// ---------------------------------------------------------------------------
// Internal: mergeWithBuiltins
// ---------------------------------------------------------------------------

/**
 * Seed the built-in contribution kinds and overlay any consumer-supplied
 * collectors on top:
 * - grants: a `GrantCollector` over one `GrantRegistry`, which holds the
 *   handlers and answers every call (`register` / `replace` throw
 *   `GrantRegistryError`).
 * - the other name-keyed kinds: a Map-backed `NameKeyedCollector`, the only
 *   registry of its kind.
 * - auditHooks, grantPolicyHooks, grantMiddleware, tokenBindingMechanisms,
 *   discoveryMetadata: identity-dedup `ListCollector`.
 * - routes: declaration-indexed `RouteCollector`.
 *
 * @internal Exported for its test; `createApp` is its one caller.
 */
export function mergeWithBuiltins(
	consumer: ContributionKindMap | undefined,
): ContributionCollectorMap {
	// Explicit type arguments carry each slot's concrete contributes-map type
	// into its collector.
	const builtin: ContributionCollectorMap = {
		grants: makeGrantCollector(),
		tokenExchangeValidators: makeMapNameKeyedCollector<ExchangeTokenValidator>(),
		federations: makeMapNameKeyedCollector<FederationProvider>(),
		federationRedirectPolicies: makeMapNameKeyedCollector<unknown>(),
		mfaFactors: makeMapNameKeyedCollector<MfaFactor | null>(),
		sessionRequirements: withoutReplace(makeMapNameKeyedCollector<RegisteredRequirement>()),
		rateLimitBudgets: makeMapNameKeyedCollector<RateLimitSpec | null>(),
		federationTypes: makeMapNameKeyedCollector<RegisteredFederationType>(),
		admissionActions: makeMapNameKeyedCollector<AdmissionAction>(),
		sessionCloseNotifiers: makeMapNameKeyedCollector<SessionCloseNotifier>(),
		auditHooks: makeIdentityDedupListCollector<AuditHook>(),
		routes: makeRouteCollector(),
		grantPolicyHooks: makeIdentityDedupListCollector<GrantPolicyHookContribution>(),
		grantMiddleware: makeIdentityDedupListCollector<RequestHandler | null>(),
		tokenBindingMechanisms: makeIdentityDedupListCollector<TokenBindingMechanism | null>(),
		discoveryMetadata: makeIdentityDedupListCollector<OidcDiscoveryContribution>(),
	};
	// Consumer keys override built-ins; unknown consumer kinds pass through.
	return { ...builtin, ...(consumer ?? {}) } as ContributionCollectorMap;
}

// ---------------------------------------------------------------------------
// Internal helpers — NOT exported from this module
// ---------------------------------------------------------------------------

/**
 * Build the `grants` `GrantCollector` over one `GrantRegistry`. The
 * registry is the only store: `entries()` — what `grantHandlerResolver`
 * lists — reads the same map `get` does. `get` answers `null` for a grant
 * type registered switched off, so boot's pre-scan sees it claimed;
 * `entries()` leaves it out.
 *
 * @internal
 */
function makeGrantCollector(): GrantCollector {
	const registry = new GrantRegistry();

	return {
		kind: "name-keyed" as const,
		register(name: string, value: GrantHandler | null): void {
			registry.register(name, value);
		},
		replace(name: string, value: GrantHandler | null): void {
			registry.replace(name, value);
		},
		freeze(): void {
			registry.freeze();
		},
		get(name: string): GrantHandler | null | undefined {
			return registry.has(name) ? (registry.get(name) ?? null) : undefined;
		},
		entries(): IterableIterator<readonly [string, GrantHandler]> {
			return registry.entries();
		},
	};
}

/**
 * The `sessionRequirements` collector refuses `replace` outright: a
 * requirement is switched off by not installing it, and nothing may swap one
 * from behind the consumers, by any path the collector offers.
 * @internal
 */
function withoutReplace<T>(collector: NameKeyedCollector<T>): NameKeyedCollector<T> {
	return {
		...collector,
		replace(name: string): void {
			throw new Error(
				`NameKeyedCollector: sessionRequirements refuses replace of "${name}": a requirement is switched off by not installing it`,
			);
		},
	};
}

/**
 * Build a plain `Map`-backed `NameKeyedCollector<T>`, typed by the caller's
 * contributes-map slot type (e.g. `<MfaFactor>`). The Map is the only
 * registry of its kind and keeps the whole `NameKeyedCollector` contract:
 * `register` throws on a duplicate and `replace` on an unknown name, both
 * throw after `freeze()`, and `entries()` lists in registration order.
 *
 * @internal
 */
function makeMapNameKeyedCollector<T>(): NameKeyedCollector<T> {
	const m = new Map<string, T>();
	let frozen = false;

	return {
		kind: "name-keyed" as const,
		register(name: string, value: T): void {
			if (frozen) {
				throw new Error(`NameKeyedCollector: frozen; cannot register "${name}"`);
			}
			if (m.has(name)) {
				throw new Error(
					`NameKeyedCollector: duplicate key "${name}" (registered: ${[...m.keys()].join(", ")})`,
				);
			}
			m.set(name, value);
		},
		replace(name: string, value: T): void {
			if (frozen) {
				throw new Error(`NameKeyedCollector: frozen; cannot replace "${name}"`);
			}
			if (!m.has(name)) {
				throw new Error(
					`NameKeyedCollector: unknown key "${name}" (registered: ${[...m.keys()].join(", ")})`,
				);
			}
			m.set(name, value);
		},
		freeze(): void {
			frozen = true;
		},
		get(name: string): T | undefined {
			return m.get(name);
		},
		entries(): IterableIterator<readonly [string, T]> {
			return m.entries() as IterableIterator<readonly [string, T]>;
		},
	};
}

/**
 * Build a `ListCollector<T>` with same-instance deduplication, typed by the
 * caller's contributes-map slot type (e.g. `<AuditHook>`). Appending the same
 * reference again is silently skipped.
 *
 * @internal
 */
function makeIdentityDedupListCollector<T>(): ListCollector<T> {
	const arr: T[] = [];
	const seen = new Set<T>();
	let frozen = false;

	return {
		kind: "list" as const,
		append(value: T): void {
			if (frozen) {
				throw new Error("ListCollector: frozen; cannot append");
			}
			if (seen.has(value)) {
				return; // Silently skip: same-instance dedup.
			}
			seen.add(value);
			arr.push(value);
		},
		freeze(): void {
			frozen = true;
		},
		values(): IterableIterator<T> {
			return arr.values();
		},
	};
}

/**
 * Build a `RouteCollector` that accumulates `CollectedRouteContribution`
 * records in declaration order. `freeze()` is mandatory on `RouteCollector`;
 * after it, `append` throws.
 *
 * @internal
 */
function makeRouteCollector(): RouteCollector {
	const arr: CollectedRouteContribution[] = [];
	let frozen = false;

	return {
		kind: "list-routes" as const,
		append(value: CollectedRouteContribution): void {
			if (frozen) {
				throw new Error("RouteCollector: frozen; cannot append");
			}
			arr.push(value);
		},
		freeze(): void {
			frozen = true;
		},
		values(): IterableIterator<CollectedRouteContribution> {
			return arr.values();
		},
	};
}
