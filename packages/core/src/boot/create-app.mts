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
 * boot/create-app.mts — The orchestrator for the A2-β boot planner pipeline.
 *
 * Wires stages 1-6 (`validateManifests → planBoot → materializeComponents →
 * applyContributions → freezeWorld → assembleApp`) into a single async
 * `createApp` function. The orchestrator owns no per-call state: it receives
 * inputs, calls each stage function in order, and forwards the output.
 *
 * Built-in defaults for the seven contribution kinds are seeded by
 * `mergeWithBuiltins`; consumer-supplied kinds (via `contributionKinds`)
 * overlay on top.
 *
 * Per A2-β §6.2 / §6.4 / §9.
 */

import type { Router } from "express";
import { createLifecycleRegistrar } from "../adapters/AdapterFactory.mjs";
import { GrantRegistry } from "../grants/registry.mjs";
import type {
	AuditHook,
	ExchangeTokenValidator,
	FederationProvider,
	GrantHandler,
	GrantPolicyHookContribution,
	MfaFactor,
} from "../modules/manifest/contributes-map.mjs";
import { applyContributions } from "./apply-contributions.mjs";
import { assembleApp } from "./assemble-app.mjs";
import { freezeWorld } from "./freeze-world.mjs";
import { materializeComponents } from "./materialize-components.mjs";
import { planBoot } from "./plan-boot.mjs";
import type {
	AppHandle,
	BootstrapMap,
	CollectedRouteContribution,
	ContributionCollectorMap,
	ContributionKindMap,
	CreateAppOptions,
	DefaultBootstrapMap,
	ListCollector,
	NameKeyedCollector,
	RouteCollector,
} from "./types.mjs";
import { validateManifests } from "./validate-manifests.mjs";

// ---------------------------------------------------------------------------
// Public API — createApp (Per A2-β §6.2 / §6.4)
// ---------------------------------------------------------------------------

/**
 * Orchestrator for the A2-β boot planner pipeline.
 *
 * Stages:
 *   1. validateManifests — normalise + validate all manifests.
 *   2. planBoot — build dependency graph, detect cycles, compute init order.
 *   3. materializeComponents — run provider factories in topological order.
 *   4. applyContributions — route contributions to collectors.
 *   5. freezeWorld — Object.freeze component map + call freeze() on registries.
 *   6. assembleApp — mount routes, build AppHandle.
 *
 * Built-in contribution kinds (grants, tokenExchangeValidators, federations,
 * mfaFactors, auditHooks, routes, grantPolicyHooks) are seeded by
 * `mergeWithBuiltins`; consumer-supplied kinds overlay on top.
 *
 * The generic `B` constrains `bootstrapComponents` to a typed subset of
 * `ComponentMap` so downstream stages receive a well-typed config/pathResolver.
 *
 * Per A2-β §6.2 / §6.4.
 */
export async function createApp<B extends BootstrapMap = DefaultBootstrapMap>(
	options: CreateAppOptions<B>,
): Promise<AppHandle> {
	const { modules, bootstrapComponents, contributionKinds, overrideComponents } = options;

	// Merge consumer kinds on top of built-in defaults. Per A2-β §6.2.
	const merged = mergeWithBuiltins(contributionKinds);

	// Stage 1: validateManifests. Per A2-β §5.1.
	// validated.bootstrapComponents carries the parsed config (Zod defaults /
	// transforms applied). All downstream stages must use it instead of the
	// raw bootstrapComponents. Per A2-β §5.1 step 13.
	const validated = validateManifests({
		modules,
		bootstrapComponents,
		contributionKinds: merged,
		overrideComponents,
	});
	const validatedBootstrap = validated.bootstrapComponents;

	// D-5: Pre-seed the lifecycle registrar as a bootstrap component so modules
	// that declare `optional: ["lifecycleRegistrar"]` receive it via deps and
	// can forward it into `createAdapterFactory(kind, { lifecycle: ... })`.
	// Owned by the boot planner (not consumer-overridable — guarded in
	// validateManifests via `bootstrap-component-collision` if a consumer
	// supplies it via overrideComponents).
	const lifecycleReg = createLifecycleRegistrar();
	const bootstrapWithLifecycle = {
		...validatedBootstrap,
		lifecycleRegistrar: lifecycleReg,
	} as typeof validatedBootstrap;

	try {
		// Stage 2: planBoot. Per A2-β §5.2.
		const plan = planBoot(validated, bootstrapWithLifecycle, overrideComponents);

		// Stage 3: materializeComponents. Per A2-β §5.3.
		const material = await materializeComponents(plan, bootstrapWithLifecycle, overrideComponents);

		// Stage 4: applyContributions. Per A2-β §5.4.
		const registry = await applyContributions(material, merged);

		// Stage 5: freezeWorld. Per A2-β §5.5.
		const frozen = freezeWorld(registry);

		// Pre-import express before calling the synchronous assembleApp.
		// assembleApp is synchronous but needs express.Router; pre-importing here
		// (in the async orchestrator) avoids making assembleApp async.
		// Per task §6.3 pattern: orchestrator does `await import("express")` and
		// passes the result to assembleApp via options.express.
		let expressMod: { Router: () => Router } | undefined;
		try {
			expressMod = (await import("express")) as { Router: () => Router };
		} catch {
			// express is an optional peer dep; assembleApp will fall back to
			// createRequire if not resolvable via dynamic import.
			expressMod = undefined;
		}

		// Stage 6: assembleApp. Per A2-β §5.6 / §6.3.
		return assembleApp(frozen, { express: expressMod, lifecycleReg });
	} catch (err) {
		// D-5 partial-boot failure: any builder may have already registered a
		// cleanup callback before a later stage threw. Best-effort drain so
		// adapter sub-resources do not leak when boot fails.
		await lifecycleReg._drain({
			// Boot-failure path: no AppHandle exists yet, so no Logger slot to
			// resolve. console.error is the only available emission channel.
			error: (obj) => console.error("[boot-failure lifecycle drain]", obj),
		});
		throw err;
	}
}

// ---------------------------------------------------------------------------
// Internal: mergeWithBuiltins (Per A2-β §6.2)
// ---------------------------------------------------------------------------

/**
 * Seed the seven built-in contribution kinds and overlay any consumer-supplied
 * collectors on top.
 *
 * Built-in defaults:
 * - grants: `GrantRegistry`-backed `NameKeyedCollector` with shadow Map for
 *   `entries()`. The `GrantRegistry` is the source of truth for `register`
 *   semantics (throw on duplicate) and `freeze`. entries() reads from the
 *   shadow Map.
 *   NOTE: `GrantRegistry` does not currently expose `entries()`. A shadow Map
 *   mirrors every `register`/`replace` call. Future cleanup: upstream
 *   `entries()` to `GrantRegistry` directly (Option B from task spec).
 * - tokenExchangeValidators: Map-backed `NameKeyedCollector`. The
 *   `ExchangeTokenValidatorRegistry` lives in a separate package
 *   (`oauth-token-exchange`) that `core` does not depend on; a plain Map
 *   implementation satisfies the `NameKeyedCollector` contract without a
 *   cross-package import. Same cleanup opportunity: if the registry is moved
 *   into core, switch to registry-backed form.
 * - federations, mfaFactors: Map-backed `NameKeyedCollector`.
 * - auditHooks, grantPolicyHooks: identity-dedup `ListCollector`.
 * - routes: declaration-indexed `RouteCollector`.
 *
 * @internal
 */
function mergeWithBuiltins(consumer: ContributionKindMap | undefined): ContributionCollectorMap {
	// AS-M1 (PR6): explicit type arguments are required for the four kinds
	// whose contributes-map placeholders were narrowed from `unknown` to
	// concrete same-package types in v0.5.1. The factories themselves are
	// type-parametric so the slot-side concrete type flows through.
	const builtin: ContributionCollectorMap = {
		grants: makeGrantCollector(),
		tokenExchangeValidators: makeMapNameKeyedCollector<ExchangeTokenValidator>(),
		federations: makeMapNameKeyedCollector<FederationProvider>(),
		federationRedirectPolicies: makeMapNameKeyedCollector<unknown>(),
		mfaFactors: makeMapNameKeyedCollector<MfaFactor>(),
		auditHooks: makeIdentityDedupListCollector<AuditHook>(),
		routes: makeRouteCollector(),
		grantPolicyHooks: makeIdentityDedupListCollector<GrantPolicyHookContribution>(),
	};
	// Consumer keys override built-ins; unknown consumer kinds pass through.
	return { ...builtin, ...(consumer ?? {}) } as ContributionCollectorMap;
}

// ---------------------------------------------------------------------------
// Internal helpers — NOT exported from this module
// ---------------------------------------------------------------------------

/**
 * Build a `NameKeyedCollector` backed by `GrantRegistry` for `register`,
 * `replace`, and `freeze`, with a shadow `Map` providing `entries()`.
 *
 * Option A pattern (per task spec): shadow Map mirrors every `register` /
 * `replace` call. `entries()` reads from the shadow, not the registry, because
 * `GrantRegistry` does not expose `entries()`. A future cleanup may upstream
 * `entries()` to `GrantRegistry` (Option B).
 *
 * @internal
 */
function makeGrantCollector(): NameKeyedCollector<GrantHandler> {
	const registry = new GrantRegistry();
	// Shadow Map: mirrors every register/replace for entries() support.
	const shadow = new Map<string, GrantHandler>();

	return {
		kind: "name-keyed" as const,
		register(name: string, value: GrantHandler): void {
			// Delegate to GrantRegistry for throw-on-duplicate semantics.
			registry.register(name, value);
			// Mirror into shadow (only if registry didn't throw).
			shadow.set(name, value);
		},
		replace(name: string, value: GrantHandler): void {
			// Delegate to GrantRegistry for throw-on-unknown semantics.
			registry.replace(name, value);
			// Mirror into shadow.
			shadow.set(name, value);
		},
		freeze(): void {
			registry.freeze();
		},
		get(name: string): GrantHandler | undefined {
			return registry.get(name);
		},
		entries(): IterableIterator<readonly [string, GrantHandler]> {
			return shadow.entries() as IterableIterator<readonly [string, GrantHandler]>;
		},
	};
}

/**
 * Build a plain `Map`-backed `NameKeyedCollector<unknown>`.
 *
 * Used for `tokenExchangeValidators`, `federations`, and `mfaFactors`.
 * `tokenExchangeValidators` uses this form because `ExchangeTokenValidatorRegistry`
 * lives in a separate package that `core` does not depend on. The Map
 * implementation satisfies the full `NameKeyedCollector` contract including
 * `entries()` without a cross-package import.
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
 * Build a `ListCollector<unknown>` with same-instance deduplication.
 *
 * Used for `auditHooks` and `grantPolicyHooks`. The `Set`-based identity
 * check silently skips re-registration of the same reference per A2-α §4.5.
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
				return; // Silently skip — same-instance dedup per A2-α §4.5.
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
 * records in declaration order.
 *
 * `freeze()` is mandatory on `RouteCollector` per A2-β §6.2; after freeze,
 * `append` throws.
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
