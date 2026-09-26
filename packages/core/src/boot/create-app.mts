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
 * Built-in defaults for the eleven built-in contribution kinds are seeded by
 * `mergeWithBuiltins`; consumer-supplied kinds (via `contributionKinds`)
 * overlay on top.
 *
 * Per A2-β §6.2 / §6.4 / §9.
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
import { createReadinessRegistrar } from "../readiness/registrar.mjs";
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
 * federationRedirectPolicies, mfaFactors, auditHooks, routes,
 * grantPolicyHooks, grantMiddleware, tokenBindingMechanisms,
 * discoveryMetadata) are seeded by `mergeWithBuiltins`; consumer-supplied
 * kinds overlay on top.
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
	// Same pre-seeding for readiness: a builder that opens a connection is the
	// only place that can probe it, so it needs the registrar at build time.
	const readinessReg = createReadinessRegistrar();
	const bootstrapWithLifecycle = {
		...validatedBootstrap,
		lifecycleRegistrar: lifecycleReg,
		readinessRegistrar: readinessReg,
	} as typeof validatedBootstrap;

	try {
		// Stage 2: planBoot. Per A2-β §5.2.
		const plan = planBoot(validated, bootstrapWithLifecycle, overrideComponents);

		// Stage 3: materializeComponents. Per A2-β §5.3.
		const material = await materializeComponents(
			plan,
			bootstrapWithLifecycle,
			overrideComponents,
			merged,
		);

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
		return assembleApp(frozen, { express: expressMod, lifecycleReg, readinessReg });
	} catch (err) {
		// D-5 partial-boot failure: any builder may have already registered a
		// cleanup callback before a later stage threw. Best-effort drain so
		// adapter sub-resources do not leak when boot fails. No AppHandle
		// exists, but a composition root that has a logger handed it in, as a
		// bootstrap component or an override (never both: stage 1 refuses the
		// pair) — `dispose()` logs through either — so a failed cleanup is
		// logged there, and through `consoleLogger` only when there is none.
		await lifecycleReg._drain(
			overrideComponents?.logger ?? validatedBootstrap.logger ?? consoleLogger,
			"boot_failure",
		);
		throw err;
	}
}

// ---------------------------------------------------------------------------
// Internal: mergeWithBuiltins (Per A2-β §6.2)
// ---------------------------------------------------------------------------

/**
 * Seed the eleven built-in contribution kinds and overlay any consumer-supplied
 * collectors on top.
 *
 * Built-in defaults:
 * - grants: a `NameKeyedCollector` over one `GrantRegistry`, which holds the
 *   handlers and answers every call — `register` / `replace` (throwing
 *   `GrantRegistryError`), `freeze`, `get` and `entries`.
 * - tokenExchangeValidators, federations, federationRedirectPolicies,
 *   mfaFactors: a Map-backed `NameKeyedCollector`, which is the only registry
 *   of its kind. Token-exchange validators are contributed by modules
 *   (`oauth-token-exchange` contributes the self-issued access-token one) and
 *   read back through the `tokenExchangeValidatorResolver` synthetic key.
 * - auditHooks, grantPolicyHooks, grantMiddleware, tokenBindingMechanisms,
 *   discoveryMetadata: identity-dedup `ListCollector`.
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
		mfaFactors: makeMapNameKeyedCollector<MfaFactor | null>(),
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
 * Build the `grants` `NameKeyedCollector` over one `GrantRegistry`. The
 * registry is the only store: `entries()` — what `grantHandlerResolver`
 * lists — reads the same map `get` does.
 *
 * @internal
 */
function makeGrantCollector(): NameKeyedCollector<GrantHandler> {
	const registry = new GrantRegistry();

	return {
		kind: "name-keyed" as const,
		register(name: string, value: GrantHandler): void {
			registry.register(name, value);
		},
		replace(name: string, value: GrantHandler): void {
			registry.replace(name, value);
		},
		freeze(): void {
			registry.freeze();
		},
		get(name: string): GrantHandler | undefined {
			return registry.get(name);
		},
		entries(): IterableIterator<readonly [string, GrantHandler]> {
			return registry.entries();
		},
	};
}

/**
 * Build a plain `Map`-backed `NameKeyedCollector<T>`. Generic-parametric
 * since AS-M1 (PR6): callers pass the concrete contributes-map slot type
 * (e.g. `<MfaFactor>`, `<FederationProvider>`) so the produced collector
 * matches the narrowed `ContributionCollectorMap` slot.
 *
 * Used for `tokenExchangeValidators`, `federations`,
 * `federationRedirectPolicies` and `mfaFactors`. The Map is the only registry
 * of each of those kinds, and keeps the whole `NameKeyedCollector` contract:
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
 * Build a `ListCollector<T>` with same-instance deduplication.
 * Generic-parametric since AS-M1 (PR6): callers pass the concrete
 * contributes-map slot type (e.g. `<AuditHook>`, `<GrantPolicyHookContribution>`)
 * so the produced collector matches the narrowed `ContributionCollectorMap`
 * slot.
 *
 * Used for `auditHooks`, `grantPolicyHooks`, `grantMiddleware`,
 * `tokenBindingMechanisms` and `discoveryMetadata`. The `Set`-based identity
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
