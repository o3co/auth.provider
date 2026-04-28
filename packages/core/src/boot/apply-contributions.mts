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
 * boot/apply-contributions.mts — Stage 4 of the A2-β boot planner pipeline.
 *
 * Takes the `ComponentWorld` from stage 3 plus the merged
 * `ContributionCollectorMap`, and:
 *   - Step 0: prepares synthetic read-side projections (`grantHandlerResolver`,
 *     `tokenExchangeValidatorResolver`, `federationProviders`) into the working
 *     component map before any factory runs.
 *   - Step 2: iterates modules in `BootPlan.initOrder`, pre-scanning for
 *     collector conflicts, then invoking name-keyed contribution factories and
 *     routing results to `collector.register` or `collector.replace`.
 *   - Step 3: iterates modules in input-array order, invoking list-shaped
 *     contribution factories and routing results to `collector.append`.
 *
 * Per A2-β §5.4.
 */

import type { ComponentKey } from "../modules/manifest/component-map.mjs";
import type {
	GrantHandlerResolver,
	TokenExchangeValidatorResolver,
} from "../modules/manifest/synthetic-keys.mjs";
import type {
	CleanupRecord,
	CollectedRouteContribution,
	ComponentWorld,
	ContributionCollectorMap,
	ContributionKind,
	NameKeyedCollector,
	RegistryWorld,
} from "./types.mjs";
import { BootError } from "./types.mjs";

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Build a typed deps object for a module from the working component map,
 * using the module's DepsBlueprint from the plan.
 *
 * Per A2-β §5.4 step 2 (deps materialisation from ComponentWorld).
 * @internal
 */
function buildDeps(
	components: Record<string, unknown>,
	requires: readonly ComponentKey[],
	optional: readonly ComponentKey[],
): Record<string, unknown> {
	const deps: Record<string, unknown> = {};
	for (const key of requires) {
		deps[key as string] = components[key as string];
	}
	for (const key of optional) {
		deps[key as string] = components[key as string];
	}
	return deps;
}

/**
 * Run cleanup records in REVERSE order (best-effort). Returns any errors
 * encountered so they can be collected into `details.cleanupErrors`.
 *
 * Per A2-β §5.4 step 2 (partial rollback on factory failure) and §5.3.
 * @internal
 */
async function runCleanupsReverse(cleanupRecords: readonly CleanupRecord[]): Promise<
	readonly {
		readonly module: string;
		readonly componentKey: ComponentKey;
		readonly error: unknown;
	}[]
> {
	const errors: { module: string; componentKey: ComponentKey; error: unknown }[] = [];
	for (let i = cleanupRecords.length - 1; i >= 0; i--) {
		// biome-ignore lint/style/noNonNullAssertion: index is bounded
		const record = cleanupRecords[i]!;
		try {
			await record.cleanup(record.value);
		} catch (err) {
			errors.push({ module: record.module, componentKey: record.componentKey, error: err });
		}
	}
	return errors;
}

/**
 * Instantiate a stable read-side `GrantHandlerResolver` backed by the given
 * `NameKeyedCollector`. The resolver's `get` / `entries` read through to the
 * collector at call time; the collector need not be populated yet when the
 * resolver reference is created.
 *
 * Per A2-β §5.4 step 0: lazy read-through means factories that capture this
 * resolver in their closure see the fully-populated view at request time.
 * @internal
 */
function makeGrantHandlerResolver(collector: NameKeyedCollector<unknown>): GrantHandlerResolver {
	return {
		get: (grantType: string) => collector.get(grantType) as ReturnType<GrantHandlerResolver["get"]>,
		entries: () => collector.entries() as ReturnType<GrantHandlerResolver["entries"]>,
	};
}

/**
 * Instantiate a stable read-side `TokenExchangeValidatorResolver` backed by
 * the given `NameKeyedCollector`.
 *
 * Per A2-β §5.4 step 0.
 * @internal
 */
function makeTokenExchangeValidatorResolver(
	collector: NameKeyedCollector<unknown>,
): TokenExchangeValidatorResolver {
	return {
		get: (tokenType: string) =>
			collector.get(tokenType) as ReturnType<TokenExchangeValidatorResolver["get"]>,
		entries: () => collector.entries() as ReturnType<TokenExchangeValidatorResolver["entries"]>,
	};
}

/**
 * Instantiate a stable `ReadonlyMap`-shaped view of a federation collector.
 * Reads through at call time via the collector's `entries()`. Backed by a
 * live `Map` snapshot taken on each access so that `ReadonlyMap` typed
 * return values (including iterator shapes) are satisfied correctly.
 *
 * Per A2-β §5.4 step 0: `federations → federationProviders` projection.
 * @internal
 */
function makeFederationProviders(
	collector: NameKeyedCollector<unknown>,
): ReadonlyMap<string, unknown> {
	function snapshot(): Map<string, unknown> {
		return new Map(collector.entries());
	}
	return {
		get: (key: string) => collector.get(key),
		has: (key: string) => collector.get(key) !== undefined,
		entries: () => snapshot().entries(),
		keys: () => snapshot().keys(),
		values: () => snapshot().values(),
		forEach: (
			cb: (value: unknown, key: string, map: ReadonlyMap<string, unknown>) => void,
			thisArg?: unknown,
		) => {
			snapshot().forEach((v, k) => {
				cb.call(thisArg, v, k, snapshot());
			});
		},
		get size() {
			return snapshot().size;
		},
		[Symbol.iterator]: () => snapshot()[Symbol.iterator](),
	};
}

/**
 * Step 0 — prepareSyntheticProjections.
 *
 * For each name-keyed collector that has a corresponding synthetic
 * `ComponentMap` projection, instantiate a stable read-side resolver and
 * write it into the working component map under the synthetic key.
 *
 * Only injects the resolver if the corresponding collector is present in the
 * `contributionKinds` map. Does NOT inject `undefined`.
 *
 * Per A2-β §5.4 step 0.
 * @internal
 */
function prepareSyntheticProjections(
	components: Record<string, unknown>,
	contributionKinds: ContributionCollectorMap,
): void {
	if (contributionKinds.grants !== undefined) {
		const resolver = makeGrantHandlerResolver(
			contributionKinds.grants as NameKeyedCollector<unknown>,
		);
		components.grantHandlerResolver = resolver;
	}
	if (contributionKinds.tokenExchangeValidators !== undefined) {
		const resolver = makeTokenExchangeValidatorResolver(
			contributionKinds.tokenExchangeValidators as NameKeyedCollector<unknown>,
		);
		components.tokenExchangeValidatorResolver = resolver;
	}
	if (contributionKinds.federations !== undefined) {
		const view = makeFederationProviders(
			contributionKinds.federations as NameKeyedCollector<unknown>,
		);
		components.federationProviders = view;
	}
}

// ---------------------------------------------------------------------------
// Name-keyed kinds set (mirrors validate-manifests.mts)
// ---------------------------------------------------------------------------

const NAME_KEYED_KINDS = new Set<string>([
	"grants",
	"federations",
	"tokenExchangeValidators",
	"mfaFactors",
]);

// ---------------------------------------------------------------------------
// Public API — applyContributions
// ---------------------------------------------------------------------------

/**
 * Stage 4 of the A2-β boot planner pipeline.
 *
 * Takes the `ComponentWorld` from stage 3 plus the merged
 * `ContributionCollectorMap` (built-in defaults + consumer overrides; the
 * orchestrator at Task 9 performs the merge before calling this function).
 *
 * Steps:
 *   0. `prepareSyntheticProjections` — inject stable read-side resolvers for
 *      `grants`, `tokenExchangeValidators`, `federations` into the working
 *      component map so contribution factories can capture resolver references
 *      that are fully populated at request time.
 *   2. Name-keyed pass (in `BootPlan.initOrder`):
 *        - Pre-scan phase: validate no duplicate/missing-target in collector
 *          state BEFORE running any factory for this module. This is the Phase 3
 *          carry-forward from GrantRegistry.addModule fix (commit de1ddb92) —
 *          prevents factory side-effect leak when one module's contribution set
 *          fails midway.
 *          Per project_v050_phase3_complete memory: pre-scan pattern from
 *          GrantRegistry.addModule fix (de1ddb92).
 *        - Materialize+register phase: invoke factories, route to
 *          `collector.register` (contributes) or `collector.replace` (overrides).
 *   3. List-shaped pass (in INPUT-ARRAY order):
 *        - auditHooks / grantPolicyHooks: invoke factory, call `collector.append`
 *          (dedup by reference identity is the collector's responsibility).
 *        - routes: invoke factory or take static value; wrap as
 *          `CollectedRouteContribution`; assign `declarationIndex`.
 *
 * On factory throw: wrap as `BootError reason="contribute-factory-failed"`,
 * `cause = thrown`, `stage = "applyContributions"`. Run stage-3 cleanups
 * from `material.cleanups` in REVERSE before propagating.
 *
 * Per A2-β §5.4.
 */
export async function applyContributions(
	material: ComponentWorld,
	contributionKinds: ContributionCollectorMap,
): Promise<RegistryWorld> {
	// ---------------------------------------------------------------------------
	// Mutable working component map (stage 3 handed it as Readonly<Partial<...>>
	// but it is not yet Object.frozen — freezeWorld does that in stage 5).
	// We cast to a plain Record so we can write the synthetic projections.
	// ---------------------------------------------------------------------------
	const components = material.components as Record<string, unknown>;

	// ---------------------------------------------------------------------------
	// Step 0: prepareSyntheticProjections. Per A2-β §5.4 step 0.
	// ---------------------------------------------------------------------------
	prepareSyntheticProjections(components, contributionKinds);

	// ---------------------------------------------------------------------------
	// Step 2: Name-keyed pass in BootPlan.initOrder.
	// Per A2-β §5.4 step 2.
	// ---------------------------------------------------------------------------

	for (const moduleName of material.plan.initOrder) {
		const validatedModule = material.plan.validated.byName.get(moduleName);
		if (!validatedModule) continue;

		const blueprint = material.plan.depsBlueprint.get(moduleName);
		const deps = buildDeps(components, blueprint?.requires ?? [], blueprint?.optional ?? []);

		// Collect name-keyed contributes + overrides entries for this module.
		const nameKeyedContributes = validatedModule.normalised.contributesEntries.filter((e) =>
			NAME_KEYED_KINDS.has(e.kind),
		);
		const nameKeyedOverrides = validatedModule.normalised.overridesEntries.filter((e) =>
			NAME_KEYED_KINDS.has(e.kind),
		);

		// ------------------------------------------------------------------
		// Pre-scan phase (Phase 3 carry-forward — prevent side-effect leak).
		// Per project_v050_phase3_complete memory: pre-scan pattern from
		// GrantRegistry.addModule fix (de1ddb92).
		//
		// Validate ALL collector invariants for this module BEFORE invoking
		// any factory. If any check fails, no factory for this module runs.
		// ------------------------------------------------------------------

		for (const entry of nameKeyedContributes) {
			const collector = (contributionKinds as Record<string, unknown>)[entry.kind] as
				| NameKeyedCollector<unknown>
				| undefined;
			if (collector === undefined) continue;
			const name = entry.key as string;
			if (collector.get(name) !== undefined) {
				throw new BootError({
					message: `Pre-scan: duplicate contribution "${name}" for kind "${entry.kind}" in module "${moduleName}".`,
					reason: "duplicate-contribute",
					stage: "applyContributions",
					details: {
						reason: "duplicate-contribute",
						kind: entry.kind,
						identity: name,
						identityKind: "name",
						modules: [moduleName, moduleName] as [string, string],
					},
				});
			}
		}

		for (const entry of nameKeyedOverrides) {
			const collector = (contributionKinds as Record<string, unknown>)[entry.kind] as
				| NameKeyedCollector<unknown>
				| undefined;
			if (collector === undefined) continue;
			const name = entry.key as string;
			if (collector.get(name) === undefined) {
				throw new BootError({
					message: `Pre-scan: override target "${name}" for kind "${entry.kind}" missing in module "${moduleName}".`,
					reason: "override-target-missing",
					stage: "applyContributions",
					details: {
						reason: "override-target-missing",
						kind: entry.kind,
						name,
						overridingModule: moduleName,
					},
				});
			}
		}

		// ------------------------------------------------------------------
		// Materialize+register phase.
		// ------------------------------------------------------------------

		for (const entry of nameKeyedContributes) {
			const collector = (contributionKinds as Record<string, unknown>)[entry.kind] as
				| NameKeyedCollector<unknown>
				| undefined;
			if (collector === undefined) continue;
			const name = entry.key as string;
			const factory = entry.factory as (deps: Record<string, unknown>) => unknown;

			let value: unknown;
			try {
				value = await factory(deps);
			} catch (thrownValue) {
				const cleanupErrors = await runCleanupsReverse(material.cleanups);
				throw new BootError({
					message: `Module "${moduleName}" contribution factory for kind "${entry.kind}" name "${name}" failed: ${String(thrownValue)}`,
					reason: "contribute-factory-failed",
					stage: "applyContributions",
					details: {
						reason: "contribute-factory-failed",
						module: moduleName,
						kind: entry.kind,
						name,
						originalError: thrownValue,
						...(cleanupErrors.length > 0 ? { cleanupErrors } : {}),
					},
					cause: thrownValue,
				});
			}

			collector.register(name, value);
		}

		for (const entry of nameKeyedOverrides) {
			const collector = (contributionKinds as Record<string, unknown>)[entry.kind] as
				| NameKeyedCollector<unknown>
				| undefined;
			if (collector === undefined) continue;
			const name = entry.key as string;
			const factory = entry.factory as (deps: Record<string, unknown>) => unknown;

			let value: unknown;
			try {
				value = await factory(deps);
			} catch (thrownValue) {
				const cleanupErrors = await runCleanupsReverse(material.cleanups);
				throw new BootError({
					message: `Module "${moduleName}" override factory for kind "${entry.kind}" name "${name}" failed: ${String(thrownValue)}`,
					reason: "contribute-factory-failed",
					stage: "applyContributions",
					details: {
						reason: "contribute-factory-failed",
						module: moduleName,
						kind: entry.kind,
						name,
						originalError: thrownValue,
						...(cleanupErrors.length > 0 ? { cleanupErrors } : {}),
					},
					cause: thrownValue,
				});
			}

			collector.replace(name, value);
		}
	}

	// ---------------------------------------------------------------------------
	// Step 3: List-shaped pass in INPUT-ARRAY order.
	// Per A2-β §5.4 step 3.
	// ---------------------------------------------------------------------------

	const routes: CollectedRouteContribution[] = [];
	let declarationIndex = 0;

	for (const validatedModule of material.plan.validated.modules) {
		const moduleName = validatedModule.normalised.name;
		const blueprint = material.plan.depsBlueprint.get(moduleName);
		const deps = buildDeps(components, blueprint?.requires ?? [], blueprint?.optional ?? []);

		// auditHooks
		const auditEntries = validatedModule.normalised.contributesEntries.filter(
			(e) => e.kind === "auditHooks",
		);
		for (const entry of auditEntries) {
			const collector = contributionKinds.auditHooks;
			if (collector === undefined) continue;
			const factory = entry.factory as (deps: Record<string, unknown>) => unknown;

			let value: unknown;
			try {
				value = await factory(deps);
			} catch (thrownValue) {
				const cleanupErrors = await runCleanupsReverse(material.cleanups);
				throw new BootError({
					message: `Module "${moduleName}" auditHook factory failed: ${String(thrownValue)}`,
					reason: "contribute-factory-failed",
					stage: "applyContributions",
					details: {
						reason: "contribute-factory-failed",
						module: moduleName,
						kind: "auditHooks",
						name: "",
						originalError: thrownValue,
						...(cleanupErrors.length > 0 ? { cleanupErrors } : {}),
					},
					cause: thrownValue,
				});
			}

			collector.append(value);
		}

		// grantPolicyHooks
		const policyEntries = validatedModule.normalised.contributesEntries.filter(
			(e) => e.kind === "grantPolicyHooks",
		);
		for (const entry of policyEntries) {
			const collector = contributionKinds.grantPolicyHooks;
			if (collector === undefined) continue;
			const factory = entry.factory as (deps: Record<string, unknown>) => unknown;

			let value: unknown;
			try {
				value = await factory(deps);
			} catch (thrownValue) {
				const cleanupErrors = await runCleanupsReverse(material.cleanups);
				throw new BootError({
					message: `Module "${moduleName}" grantPolicyHook factory failed: ${String(thrownValue)}`,
					reason: "contribute-factory-failed",
					stage: "applyContributions",
					details: {
						reason: "contribute-factory-failed",
						module: moduleName,
						kind: "grantPolicyHooks",
						name: "",
						originalError: thrownValue,
						...(cleanupErrors.length > 0 ? { cleanupErrors } : {}),
					},
					cause: thrownValue,
				});
			}

			collector.append(value);
		}

		// routes
		const routeEntries = validatedModule.normalised.contributesEntries.filter(
			(e) => e.kind === "routes",
		);
		for (const entry of routeEntries) {
			const routeCollector = contributionKinds.routes;

			// entry.factory is a RouteContributionEntry<Deps>:
			// either a bare RouteContribution value or a RouteContributionFactory<Deps>.
			const entryValue = entry.factory;
			let contribution: unknown;

			if (typeof entryValue === "function") {
				// Factory form — invoke with deps.
				try {
					contribution = await (entryValue as (deps: Record<string, unknown>) => unknown)(deps);
				} catch (thrownValue) {
					const cleanupErrors = await runCleanupsReverse(material.cleanups);
					throw new BootError({
						message: `Module "${moduleName}" route factory failed: ${String(thrownValue)}`,
						reason: "contribute-factory-failed",
						stage: "applyContributions",
						details: {
							reason: "contribute-factory-failed",
							module: moduleName,
							kind: "routes",
							name: "",
							originalError: thrownValue,
							...(cleanupErrors.length > 0 ? { cleanupErrors } : {}),
						},
						cause: thrownValue,
					});
				}
			} else {
				// Static RouteContribution value — take directly.
				contribution = entryValue;
			}

			const collected: CollectedRouteContribution = {
				contribution:
					contribution as import("../modules/manifest/route-contribution.mjs").RouteContribution,
				contributedBy: moduleName,
				declarationIndex,
			};

			declarationIndex++;

			routes.push(collected);

			if (routeCollector !== undefined) {
				routeCollector.append(collected);
			}
		}
	}

	// ---------------------------------------------------------------------------
	// Build registries map: kind → collector reference. Stage 5 uses this to
	// call freeze() on each collector that exposes it.
	// Per A2-β §5.4 output.
	// ---------------------------------------------------------------------------
	const registries = new Map<ContributionKind, unknown>();
	for (const [kind, collector] of Object.entries(contributionKinds)) {
		if (collector !== undefined) {
			registries.set(kind as ContributionKind, collector);
		}
	}

	return {
		material,
		registries: registries as ReadonlyMap<ContributionKind, unknown>,
		routes,
	};
}
