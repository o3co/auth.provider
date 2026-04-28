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
 * boot/validate-manifests.mts — Stage 1 of the A2-β boot planner pipeline.
 *
 * Accepts the consumer's `Module[]`, `bootstrapComponents`,
 * `contributionKinds`, and `overrideComponents`; runs 14 ordered sub-checks
 * against the manifests; emits `ValidatedManifests` on success or throws a
 * typed `BootError` on the first violation in input-array order.
 *
 * The stage is **deterministic and side-effect-free**: same inputs → same
 * output / same error.
 *
 * Per A2-β §5.1.
 */

import { z } from "zod";
import { composeConfigSchema } from "../config/application.schema.mjs";
import type { ComponentKey, ComponentMap } from "../modules/manifest/component-map.mjs";
import type { Module } from "../modules/manifest/module-spec.mjs";
import type { RouteContribution } from "../modules/manifest/route-contribution.mjs";
import { SYNTHETIC_COMPONENT_KEYS } from "../modules/manifest/synthetic-keys.mjs";
import type {
	BootstrapMap,
	ContributionEntry,
	ContributionKind,
	ContributionKindMap,
	NormalisedModule,
	ValidatedManifests,
	ValidatedModule,
} from "./types.mjs";
import { BootError } from "./types.mjs";

// ---------------------------------------------------------------------------
// Public input type
// ---------------------------------------------------------------------------

/**
 * Input shape accepted by `validateManifests`. Mirrors `CreateAppOptions`
 * minus the generic `B` parameter (the bootstrap map is typed at the
 * `createApp` call site; stage 1 receives it erased to `BootstrapMap`).
 *
 * Per A2-β §5.1.
 */
export interface ValidateManifestsInput {
	readonly modules: readonly Module[];
	readonly bootstrapComponents: BootstrapMap;
	readonly contributionKinds?: ContributionKindMap;
	readonly overrideComponents?: Partial<ComponentMap>;
}

// ---------------------------------------------------------------------------
// Module normalisation (per plan §3.3 normaliseModule)
// ---------------------------------------------------------------------------

/**
 * Flatten a raw Module manifest into a NormalisedModule for fast lookup
 * by subsequent checks. Collects:
 * - `requires` / `optional` key arrays
 * - `providesKeys` from `Object.keys(module.provides ?? {})`
 * - `contributesEntries` / `overridesEntries` as flat ContributionEntry[]
 * - `lifecycleKeys` from `Object.keys(module.lifecycle ?? {})`
 *
 * @internal
 */
function normaliseModule(m: Module): NormalisedModule {
	const requires = (m.requires ?? []) as readonly ComponentKey[];
	const optional = (m.optional ?? []) as readonly ComponentKey[];
	const providesKeys = Object.keys(m.provides ?? {}) as ComponentKey[];

	const contributesEntries: ContributionEntry[] = [];
	for (const [kind, kindMap] of Object.entries(m.contributes ?? {})) {
		if (Array.isArray(kindMap)) {
			// List-shaped kinds: auditHooks, routes, grantPolicyHooks
			for (const factory of kindMap) {
				contributesEntries.push({
					kind: kind as ContributionKind,
					key: Symbol(kind),
					factory,
					contributedBy: m.name,
				});
			}
		} else if (kindMap !== null && typeof kindMap === "object") {
			// Name-keyed kinds: grants, federations, tokenExchangeValidators, mfaFactors
			for (const [name, factory] of Object.entries(kindMap as Record<string, unknown>)) {
				contributesEntries.push({
					kind: kind as ContributionKind,
					key: name,
					factory,
					contributedBy: m.name,
				});
			}
		}
	}

	const overridesEntries: ContributionEntry[] = [];
	for (const [kind, kindMap] of Object.entries(m.overrides ?? {})) {
		if (Array.isArray(kindMap)) {
			for (const factory of kindMap) {
				overridesEntries.push({
					kind: kind as ContributionKind,
					key: Symbol(kind),
					factory,
					contributedBy: m.name,
				});
			}
		} else if (kindMap !== null && typeof kindMap === "object") {
			for (const [name, factory] of Object.entries(kindMap as Record<string, unknown>)) {
				overridesEntries.push({
					kind: kind as ContributionKind,
					key: name,
					factory,
					contributedBy: m.name,
				});
			}
		}
	}

	const lifecycleKeys = Object.keys(m.lifecycle ?? {}) as ComponentKey[];

	return {
		name: m.name,
		requires,
		optional,
		providesKeys,
		contributesEntries,
		overridesEntries,
		lifecycleKeys,
	};
}

// ---------------------------------------------------------------------------
// Built-in contribution kinds — auto-wired by core; no collector required
// ---------------------------------------------------------------------------

const BUILTIN_CONTRIBUTION_KINDS = new Set<string>([
	"grants",
	"federations",
	"tokenExchangeValidators",
	"mfaFactors",
	"auditHooks",
	"routes",
	"grantPolicyHooks",
]);

// ---------------------------------------------------------------------------
// List-shaped contribution kinds — override is not allowed for these
// ---------------------------------------------------------------------------

const LIST_SHAPED_KINDS = new Set<string>(["routes", "auditHooks", "grantPolicyHooks"]);

// ---------------------------------------------------------------------------
// Name-keyed contribution kinds — subject to per-kind name collision check
// ---------------------------------------------------------------------------

const NAME_KEYED_KINDS = new Set<string>([
	"grants",
	"federations",
	"tokenExchangeValidators",
	"mfaFactors",
]);

// ---------------------------------------------------------------------------
// Step 1 — Module identity uniqueness
// Per A2-β §5.1 step 1.
// ---------------------------------------------------------------------------

/**
 * Step 1: Two manifests with the same `name` throw `duplicate-module-name`.
 * Per A2-β §5.1 step 1.
 * @internal
 */
function checkUniqueModuleNames(modules: readonly Module[]): void {
	const seen = new Map<string, string>();
	for (const m of modules) {
		const prev = seen.get(m.name);
		if (prev !== undefined) {
			throw new BootError({
				message: `Duplicate module name "${m.name}" — two modules share the same identity.`,
				reason: "duplicate-module-name",
				stage: "validateManifests",
				details: {
					reason: "duplicate-module-name",
					name: m.name,
					modules: [prev, m.name],
				},
			});
		}
		seen.set(m.name, m.name);
	}
}

// ---------------------------------------------------------------------------
// Step 2 — Provides closure check (no duplicate providers)
// Per A2-β §5.1 step 2.
// ---------------------------------------------------------------------------

/**
 * Step 2: Two modules providing the same ComponentKey throw `duplicate-provides`.
 * Per A2-β §5.1 step 2.
 * @internal
 */
function checkProvidesClosure(modules: readonly NormalisedModule[]): void {
	const providers = new Map<ComponentKey, string>();
	for (const m of modules) {
		for (const key of m.providesKeys) {
			const prev = providers.get(key);
			if (prev !== undefined) {
				throw new BootError({
					message: `Duplicate provides key "${key}" — modules "${prev}" and "${m.name}" both provide it.`,
					reason: "duplicate-provides",
					stage: "validateManifests",
					details: {
						reason: "duplicate-provides",
						componentKey: key,
						modules: [prev, m.name],
					},
				});
			}
			providers.set(key, m.name);
		}
	}
}

// ---------------------------------------------------------------------------
// Step 3 — Bootstrap closure, substitution-channel disjointness, and
//          synthetic-key constraint.
// Per A2-β §5.1 step 3.
// ---------------------------------------------------------------------------

/**
 * Step 3: Check bootstrap/overrideComponents/synthetic-key constraints.
 * Per A2-β §5.1 step 3.
 * @internal
 */
function checkBootstrapAndSyntheticDisjointness(
	modules: readonly NormalisedModule[],
	bootstrap: BootstrapMap,
	override: Partial<ComponentMap> | undefined,
): void {
	const bootstrapKeys = new Set<string>(Object.keys(bootstrap));
	const overrideKeys = new Set<string>(Object.keys(override ?? {}));

	// 3a: synthetic keys must not appear in any module's provides
	for (const m of modules) {
		for (const key of m.providesKeys) {
			if (SYNTHETIC_COMPONENT_KEYS.has(key)) {
				throw new BootError({
					message: `Module "${m.name}" attempts to provide synthetic key "${key}", which is reserved for the boot planner.`,
					reason: "synthetic-key-collision",
					stage: "validateManifests",
					details: {
						reason: "synthetic-key-collision",
						componentKey: key,
						source: "module-provides",
						module: m.name,
					},
				});
			}
		}
	}

	// 3b: synthetic keys must not appear in bootstrapComponents
	for (const key of bootstrapKeys) {
		if (SYNTHETIC_COMPONENT_KEYS.has(key)) {
			throw new BootError({
				message: `bootstrapComponents contains synthetic key "${key}", which is reserved for the boot planner.`,
				reason: "synthetic-key-collision",
				stage: "validateManifests",
				details: {
					reason: "synthetic-key-collision",
					componentKey: key as ComponentKey,
					source: "bootstrapComponents",
				},
			});
		}
	}

	// 3c: synthetic keys must not appear in overrideComponents
	for (const key of overrideKeys) {
		if (SYNTHETIC_COMPONENT_KEYS.has(key)) {
			throw new BootError({
				message: `overrideComponents contains synthetic key "${key}", which is reserved for the boot planner.`,
				reason: "synthetic-key-collision",
				stage: "validateManifests",
				details: {
					reason: "synthetic-key-collision",
					componentKey: key as ComponentKey,
					source: "overrideComponents",
				},
			});
		}
	}

	// 3d: a module's provides[K] for a key also in bootstrapComponents
	//     throws bootstrap-component-collision (source: "module-provides")
	for (const m of modules) {
		for (const key of m.providesKeys) {
			if (bootstrapKeys.has(key)) {
				throw new BootError({
					message: `Module "${m.name}" provides "${key}" which is already present in bootstrapComponents.`,
					reason: "bootstrap-component-collision",
					stage: "validateManifests",
					details: {
						reason: "bootstrap-component-collision",
						componentKey: key,
						source: "module-provides",
						module: m.name,
					},
				});
			}
		}
	}

	// 3e: overrideComponents[K] whose K is also in bootstrapComponents
	//     throws bootstrap-component-collision (source: "overrideComponents")
	for (const key of overrideKeys) {
		if (bootstrapKeys.has(key)) {
			throw new BootError({
				message: `overrideComponents contains "${key}" which is already present in bootstrapComponents. These channels are mutually exclusive.`,
				reason: "bootstrap-component-collision",
				stage: "validateManifests",
				details: {
					reason: "bootstrap-component-collision",
					componentKey: key as ComponentKey,
					source: "overrideComponents",
				},
			});
		}
	}
}

// ---------------------------------------------------------------------------
// Step 4 — Requires/optional closure check + path-construction algorithm
// Per A2-β §5.1 step 4.
// ---------------------------------------------------------------------------

/**
 * Build the diagnostic `path` chain from the entry-point module (`rootModule`)
 * down to the failing module `F` along the requires→provides chain.
 *
 * Per A2-β §5.1 step 4 normative algorithm.
 * @internal
 */
function buildMissingRequiredPath(
	failingModule: NormalisedModule,
	missingKey: ComponentKey,
	modules: readonly NormalisedModule[],
	providerIndex: ReadonlyMap<ComponentKey, NormalisedModule>,
): {
	rootModule: string;
	path: readonly {
		readonly module: string;
		readonly requires: ComponentKey;
		readonly satisfiedBy?: string;
	}[];
} {
	const moduleByName = new Map<string, NormalisedModule>();
	for (const m of modules) {
		moduleByName.set(m.name, m);
	}

	// Build index-by-name for tie-breaking (earliest input-array position)
	const indexByName = new Map<string, number>();
	for (let i = 0; i < modules.length; i++) {
		indexByName.set(modules[i].name, i);
	}

	// Backward walk: from F, find the "root" by stepping to the earliest-
	// input-array requirer (the module whose requires is satisfied by F's provides).
	// Tie-break by lexicographically smallest name.
	// Halt when no requirer exists or visited-set hit.
	const visited = new Set<string>();
	let current = failingModule;
	visited.add(current.name);

	while (true) {
		// Find all modules that require some key that current provides
		let bestRequirer: NormalisedModule | undefined;
		let bestIndex = Number.MAX_SAFE_INTEGER;

		for (const m of modules) {
			if (visited.has(m.name)) continue;
			// Does m require a key that current provides?
			for (const reqKey of m.requires) {
				const provider = providerIndex.get(reqKey);
				if (provider?.name === current.name) {
					const idx = indexByName.get(m.name) ?? Number.MAX_SAFE_INTEGER;
					if (
						idx < bestIndex ||
						(idx === bestIndex && bestRequirer !== undefined && m.name < bestRequirer.name)
					) {
						bestIndex = idx;
						bestRequirer = m;
					}
					break;
				}
			}
		}

		if (bestRequirer === undefined) {
			// current is the root
			break;
		}
		visited.add(bestRequirer.name);
		current = bestRequirer;
	}

	const rootModule = current;

	// Forward walk: from rootModule to failingModule, following the chain.
	// Build path entries.
	const path: { module: string; requires: ComponentKey; satisfiedBy?: string }[] = [];

	// Walk forward: at each step, determine which requires key on the current
	// module leads toward the failing module, following the provides chain.
	const walker = rootModule;
	const walkedPath: NormalisedModule[] = [rootModule];

	// Build a path of modules from root to failing
	const moduleChain = buildModuleChain(
		rootModule,
		failingModule,
		modules,
		providerIndex,
		indexByName,
	);

	for (let i = 0; i < moduleChain.length - 1; i++) {
		const from = moduleChain[i];
		const to = moduleChain[i + 1];

		// Find the requires key on `from` that is satisfied by `to`
		// Tie-break: lexicographically smallest key
		let linkKey: ComponentKey | undefined;
		for (const reqKey of from.requires) {
			const provider = providerIndex.get(reqKey);
			if (provider?.name === to.name) {
				if (linkKey === undefined || reqKey < linkKey) {
					linkKey = reqKey;
				}
			}
		}

		if (linkKey !== undefined) {
			path.push({ module: from.name, requires: linkKey, satisfiedBy: to.name });
		}
	}
	void walker;
	void walkedPath;

	// Terminal link: the failing module with the missing key (no satisfiedBy)
	path.push({ module: failingModule.name, requires: missingKey });

	return { rootModule: rootModule.name, path };
}

/**
 * Build an ordered chain of modules from `start` to `end` following
 * the provides→requires links, using a BFS approach with earliest-
 * input-array-then-lexicographic tie-breaking.
 * @internal
 */
function buildModuleChain(
	start: NormalisedModule,
	end: NormalisedModule,
	_modules: readonly NormalisedModule[],
	providerIndex: ReadonlyMap<ComponentKey, NormalisedModule>,
	indexByName: ReadonlyMap<string, number>,
): NormalisedModule[] {
	if (start.name === end.name) {
		return [start];
	}

	// BFS from start, following requires→provides edges
	const visited = new Set<string>([start.name]);
	const queue: { node: NormalisedModule; chain: NormalisedModule[] }[] = [
		{ node: start, chain: [start] },
	];

	while (queue.length > 0) {
		// Pop the entry with the earliest module in the queue (declaration order)
		queue.sort((a, b) => {
			const ia = indexByName.get(a.node.name) ?? 0;
			const ib = indexByName.get(b.node.name) ?? 0;
			if (ia !== ib) return ia - ib;
			return a.node.name < b.node.name ? -1 : 1;
		});
		const shifted = queue.shift();
		if (shifted === undefined) break; // unreachable: guarded by while (queue.length > 0)
		const { node: current, chain } = shifted;

		// Find all modules that current requires and that exist in the provides map
		const nextCandidates: NormalisedModule[] = [];
		for (const reqKey of current.requires) {
			const provider = providerIndex.get(reqKey);
			if (provider && !visited.has(provider.name)) {
				nextCandidates.push(provider);
			}
		}

		// Sort by input-array index, then lexicographic
		nextCandidates.sort((a, b) => {
			const ia = indexByName.get(a.name) ?? 0;
			const ib = indexByName.get(b.name) ?? 0;
			if (ia !== ib) return ia - ib;
			return a.name < b.name ? -1 : 1;
		});

		for (const next of nextCandidates) {
			if (visited.has(next.name)) continue;
			visited.add(next.name);
			const newChain = [...chain, next];
			if (next.name === end.name) {
				return newChain;
			}
			queue.push({ node: next, chain: newChain });
		}
	}

	// No path found (shouldn't happen in correct usage); return start→end directly
	return [start, end];
}

/**
 * Step 4: Requires/optional closure check.
 * For each module, every key in `requires` must appear in either
 * `bootstrapComponents`, the union of all modules' `provides`, or
 * `overrideComponents`, or be in the synthetic-key set (auto-satisfied).
 * Per A2-β §5.1 step 4.
 * @internal
 */
function checkRequiresClosure(
	modules: readonly NormalisedModule[],
	bootstrap: BootstrapMap,
	override: Partial<ComponentMap> | undefined,
): void {
	const bootstrapKeys = new Set<string>(Object.keys(bootstrap));
	const overrideKeys = new Set<string>(Object.keys(override ?? {}));

	// Build a map: ComponentKey → providing NormalisedModule
	const providerIndex = new Map<ComponentKey, NormalisedModule>();
	for (const m of modules) {
		for (const key of m.providesKeys) {
			providerIndex.set(key, m);
		}
	}

	const isSatisfied = (key: ComponentKey): boolean =>
		bootstrapKeys.has(key) ||
		overrideKeys.has(key) ||
		providerIndex.has(key) ||
		SYNTHETIC_COMPONENT_KEYS.has(key);

	// Find the first module in input order whose requires contains an unsatisfied key
	for (const m of modules) {
		for (const key of m.requires) {
			if (!isSatisfied(key)) {
				const { rootModule, path } = buildMissingRequiredPath(m, key, modules, providerIndex);
				throw new BootError({
					message: `Missing required component "${key}" — module "${m.name}" requires it but no provider was found.`,
					reason: "missing-required-component",
					stage: "validateManifests",
					details: {
						reason: "missing-required-component",
						missingKey: key,
						rootModule,
						path,
					},
				});
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Step 5 — Contribution kind / collector closure
// Per A2-β §5.1 step 5.
// ---------------------------------------------------------------------------

/**
 * Step 5: Every contribution kind referenced by a module must have a
 * collector (built-in kinds are auto-wired; custom kinds need a
 * `contributionKinds` entry).
 * Per A2-β §5.1 step 5.
 * @internal
 */
function checkContributionKindCoverage(
	modules: readonly NormalisedModule[],
	contributionKinds: ContributionKindMap | undefined,
): void {
	const customKinds = new Set<string>(Object.keys(contributionKinds ?? {}));

	// Collect all kinds used across modules
	const kindToModules = new Map<string, string[]>();
	for (const m of modules) {
		const allEntries = [...m.contributesEntries, ...m.overridesEntries];
		for (const entry of allEntries) {
			const kind = entry.kind;
			let kindModules = kindToModules.get(kind);
			if (kindModules === undefined) {
				kindModules = [];
				kindToModules.set(kind, kindModules);
			}
			kindModules.push(m.name);
		}
	}

	for (const [kind, contributedBy] of kindToModules) {
		if (!BUILTIN_CONTRIBUTION_KINDS.has(kind) && !customKinds.has(kind)) {
			// Deduplicate module names
			const unique = [...new Set(contributedBy)];
			throw new BootError({
				message: `Unknown contribution kind "${kind}" — modules [${unique.join(", ")}] contribute it but no collector was provided.`,
				reason: "unknown-contribution-kind",
				stage: "validateManifests",
				details: {
					reason: "unknown-contribution-kind",
					kind,
					contributedBy: unique,
				},
			});
		}
	}
}

// ---------------------------------------------------------------------------
// Step 6 — Per-kind duplicate contributes check (name-keyed kinds)
// Per A2-β §5.1 step 6.
// ---------------------------------------------------------------------------

/**
 * Step 6: For name-keyed kinds, (kind, name) collisions across modules throw
 * `duplicate-contribute`. List-shaped kinds are handled in step 7 (routes)
 * or silently deduplicated (auditHooks, grantPolicyHooks per A2-α §4.5).
 * Per A2-β §5.1 step 6.
 * @internal
 */
function checkPerKindContributeDuplicates(modules: readonly NormalisedModule[]): void {
	// Track (kind, name) → first contributing module
	const seen = new Map<string, string>(); // key: `${kind}:${name}`

	for (const m of modules) {
		for (const entry of m.contributesEntries) {
			const kind = entry.kind;
			// Only check name-keyed kinds; list-shaped use different identity
			if (!NAME_KEYED_KINDS.has(kind)) continue;
			if (typeof entry.key !== "string") continue;

			const compoundKey = `${kind}:${entry.key}`;
			const prev = seen.get(compoundKey);
			if (prev !== undefined) {
				throw new BootError({
					message: `Duplicate contribution "${entry.key}" for kind "${kind}" — modules "${prev}" and "${m.name}" both contribute it.`,
					reason: "duplicate-contribute",
					stage: "validateManifests",
					details: {
						reason: "duplicate-contribute",
						kind,
						identity: entry.key as string,
						identityKind: "name",
						modules: [prev, m.name],
					},
				});
			}
			seen.set(compoundKey, m.name);
		}
	}
}

// ---------------------------------------------------------------------------
// Step 7 — RouteContribution collision check
// Per A2-β §5.1 step 7.
// ---------------------------------------------------------------------------

/**
 * Collect all RouteContribution objects from modules' contributes.routes
 * (only static values at validate-manifests time; factories are not invoked
 * in this stage per A2-β §5.1).
 * @internal
 */
function collectRouteContributions(
	modules: readonly NormalisedModule[],
	rawModules: readonly Module[],
): { route: RouteContribution; module: string }[] {
	const result: { route: RouteContribution; module: string }[] = [];
	for (const rawMod of rawModules) {
		const routeEntries = rawMod.contributes?.routes ?? [];
		for (const entry of routeEntries) {
			// At validate-manifests time, only static RouteContribution values can
			// be inspected. Factory entries (functions) are opaque until
			// materializeComponents runs deps. We only inspect static entries.
			if (typeof entry === "object" && entry !== null && !Array.isArray(entry)) {
				result.push({ route: entry as RouteContribution, module: rawMod.name });
			}
		}
	}
	void modules;
	return result;
}

/**
 * Step 7: RouteContribution collision check — id collision, mountPath
 * collision (no id), effective (method, mountPath+adv.path) collision, and
 * RouteAdvertisement.path leading-slash validation.
 * Per A2-β §5.1 step 7.
 * @internal
 */
function checkRouteCollisions(
	modules: readonly NormalisedModule[],
	rawModules: readonly Module[],
): void {
	// Collect all static route contributions
	const routes = collectRouteContributions(modules, rawModules);

	// 7a: Duplicate id check
	const seenIds = new Map<string, string>(); // id → module
	for (const { route, module } of routes) {
		if (route.id !== undefined) {
			const prev = seenIds.get(route.id);
			if (prev !== undefined) {
				throw new BootError({
					message: `Duplicate route id "${route.id}" — modules "${prev}" and "${module}" both declare it.`,
					reason: "duplicate-contribute",
					stage: "validateManifests",
					details: {
						reason: "duplicate-contribute",
						kind: "routes",
						identity: route.id,
						identityKind: "id",
						modules: [prev, module],
					},
				});
			}
			seenIds.set(route.id, module);
		}
	}

	// 7b: Duplicate mountPath (no id) check
	const seenMountPaths = new Map<string, string>(); // mountPath → module
	for (const { route, module } of routes) {
		if (route.id === undefined) {
			const prev = seenMountPaths.get(route.mountPath);
			if (prev !== undefined) {
				throw new BootError({
					message: `Duplicate mountPath "${route.mountPath}" (no id) — modules "${prev}" and "${module}" both declare it.`,
					reason: "duplicate-contribute",
					stage: "validateManifests",
					details: {
						reason: "duplicate-contribute",
						kind: "routes",
						identity: route.mountPath,
						identityKind: "mountPath",
						modules: [prev, module],
					},
				});
			}
			seenMountPaths.set(route.mountPath, module);
		}
	}

	// 7c + 7d: RouteAdvertisement checks
	// Check: advertisement.path must start with "/"
	// Check: effective (method, mountPath+adv.path) collision
	const seenEffective = new Map<string, { module: string; mountPath: string }>(); // identity → { module }

	for (const { route, module } of routes) {
		if (!route.routes) continue;
		for (const adv of route.routes) {
			// 7d: leading-slash check
			if (!adv.path.startsWith("/")) {
				throw new BootError({
					message: `RouteAdvertisement.path "${adv.path}" in module "${module}" (mountPath "${route.mountPath}") must start with "/".`,
					reason: "invalid-route-advertisement-path",
					stage: "validateManifests",
					details: {
						reason: "invalid-route-advertisement-path",
						module,
						mountPath: route.mountPath,
						path: adv.path,
						identityKind: "missing-leading-slash",
					},
				});
			}

			// 7c: effective method+path collision
			const effectiveIdentity = `${adv.method} ${route.mountPath}${adv.path}`;
			const prev = seenEffective.get(effectiveIdentity);
			if (prev !== undefined) {
				throw new BootError({
					message: `Effective route collision "${effectiveIdentity}" — modules "${prev.module}" and "${module}" both declare it.`,
					reason: "duplicate-contribute",
					stage: "validateManifests",
					details: {
						reason: "duplicate-contribute",
						kind: "routes",
						identity: effectiveIdentity,
						identityKind: "effective-method-path",
						modules: [prev.module, module],
					},
				});
			}
			seenEffective.set(effectiveIdentity, { module, mountPath: route.mountPath });
		}
	}
}

// ---------------------------------------------------------------------------
// Step 8 — Override target existence
// Per A2-β §5.1 step 8.
// ---------------------------------------------------------------------------

/**
 * Step 8: Every `overrides[kind][name]` must have a matching
 * `contributes[kind][name]` in some module.
 * Per A2-β §5.1 step 8.
 * @internal
 */
function checkOverrideTargets(modules: readonly NormalisedModule[]): void {
	// Build set of all contributes (kind, name) pairs
	const contributed = new Set<string>(); // `${kind}:${name}`
	for (const m of modules) {
		for (const entry of m.contributesEntries) {
			if (typeof entry.key === "string") {
				contributed.add(`${entry.kind}:${entry.key}`);
			}
		}
	}

	for (const m of modules) {
		for (const entry of m.overridesEntries) {
			if (typeof entry.key !== "string") continue;
			const compoundKey = `${entry.kind}:${entry.key}`;
			if (!contributed.has(compoundKey)) {
				throw new BootError({
					message: `Override target missing — module "${m.name}" overrides "${entry.kind}.${entry.key}" but no module contributes it.`,
					reason: "override-target-missing",
					stage: "validateManifests",
					details: {
						reason: "override-target-missing",
						kind: entry.kind,
						name: entry.key,
						overridingModule: m.name,
					},
				});
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Step 9 — Override duplicate check
// Per A2-β §5.1 step 9.
// ---------------------------------------------------------------------------

/**
 * Step 9: Two modules overriding the same (kind, name) throw
 * `duplicate-override`.
 * Per A2-β §5.1 step 9.
 * @internal
 */
function checkOverrideDuplicates(modules: readonly NormalisedModule[]): void {
	const seen = new Map<string, string>(); // `${kind}:${name}` → module
	for (const m of modules) {
		for (const entry of m.overridesEntries) {
			if (typeof entry.key !== "string") continue;
			const compoundKey = `${entry.kind}:${entry.key}`;
			const prev = seen.get(compoundKey);
			if (prev !== undefined) {
				throw new BootError({
					message: `Duplicate override for "${entry.kind}.${entry.key}" — modules "${prev}" and "${m.name}" both override it.`,
					reason: "duplicate-override",
					stage: "validateManifests",
					details: {
						reason: "duplicate-override",
						kind: entry.kind,
						name: entry.key,
						modules: [prev, m.name],
					},
				});
			}
			seen.set(compoundKey, m.name);
		}
	}
}

// ---------------------------------------------------------------------------
// Step 10 — Same-module contribute-and-override collision
// Per A2-β §5.1 step 10.
// ---------------------------------------------------------------------------

/**
 * Step 10: A single module declaring both `contributes[kind][name]` and
 * `overrides[kind][name]` for the same (kind, name) throws
 * `contribute-and-override-same-key`.
 * Per A2-β §5.1 step 10.
 * @internal
 */
function checkSameModuleContributeOverride(modules: readonly NormalisedModule[]): void {
	for (const m of modules) {
		const contributed = new Set<string>();
		for (const entry of m.contributesEntries) {
			if (typeof entry.key === "string") {
				contributed.add(`${entry.kind}:${entry.key}`);
			}
		}
		for (const entry of m.overridesEntries) {
			if (typeof entry.key !== "string") continue;
			const compoundKey = `${entry.kind}:${entry.key}`;
			if (contributed.has(compoundKey)) {
				throw new BootError({
					message: `Module "${m.name}" both contributes and overrides "${entry.kind}.${entry.key}" — these are mutually exclusive.`,
					reason: "contribute-and-override-same-key",
					stage: "validateManifests",
					details: {
						reason: "contribute-and-override-same-key",
						kind: entry.kind,
						name: entry.key,
						module: m.name,
					},
				});
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Step 11 — List-shaped override rejection
// Per A2-β §5.1 step 11.
// ---------------------------------------------------------------------------

/**
 * Step 11: A module's `overrides` carrying `routes`, `auditHooks`, or
 * `grantPolicyHooks` throws `list-shaped-override-not-allowed`.
 * Per A2-β §5.1 step 11.
 * @internal
 */
function checkListShapedOverrides(rawModules: readonly Module[]): void {
	for (const m of rawModules) {
		const overrides = m.overrides ?? {};
		for (const kind of LIST_SHAPED_KINDS) {
			if (kind in overrides) {
				throw new BootError({
					message: `Module "${m.name}" attempts to override list-shaped kind "${kind}", which is not allowed.`,
					reason: "list-shaped-override-not-allowed",
					stage: "validateManifests",
					details: {
						reason: "list-shaped-override-not-allowed",
						kind: kind as "routes" | "auditHooks" | "grantPolicyHooks",
						module: m.name,
					},
				});
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Step 12 — Lifecycle / provides closure
// Per A2-β §5.1 step 12.
// ---------------------------------------------------------------------------

/**
 * Step 12: A `lifecycle[K]` entry whose `K` does not appear in the same
 * module's `provides` throws `lifecycle-without-provides`.
 * Per A2-β §5.1 step 12.
 * @internal
 */
function checkLifecycleClosure(modules: readonly NormalisedModule[]): void {
	for (const m of modules) {
		const providesSet = new Set<ComponentKey>(m.providesKeys);
		for (const key of m.lifecycleKeys) {
			if (!providesSet.has(key)) {
				throw new BootError({
					message: `Module "${m.name}" declares lifecycle for "${key}" but does not provide it.`,
					reason: "lifecycle-without-provides",
					stage: "validateManifests",
					details: {
						reason: "lifecycle-without-provides",
						componentKey: key,
						module: m.name,
					},
				});
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Step 13 — Config schema composition and validation
// Per A2-β §5.1 step 13.
// ---------------------------------------------------------------------------

/**
 * Step 13: Compose all module `configSchema` entries into a single Zod
 * schema and validate `bootstrapComponents.config` against it.
 * On parse failure throws `config-validation-failed`.
 * Per A2-β §5.1 step 13.
 * @internal
 */
function validateAndComposeConfig(modules: readonly Module[], bootstrap: BootstrapMap): void {
	const schemas: z.ZodObject<z.ZodRawShape>[] = [];
	const participants: { readonly module: string; readonly schemaPath?: string }[] = [];

	for (const m of modules) {
		if (m.configSchema) {
			schemas.push(m.configSchema);
			participants.push({ module: m.name });
		}
	}

	if (schemas.length === 0) return;

	const composedSchema = composeConfigSchema(schemas);

	try {
		composedSchema.parse((bootstrap as Record<string, unknown>).config);
	} catch (err) {
		if (err instanceof z.ZodError) {
			throw new BootError({
				message: `Config validation failed — ${err.issues.length} issue(s) found.`,
				reason: "config-validation-failed",
				stage: "validateManifests",
				details: {
					reason: "config-validation-failed",
					issues: err.issues,
					modules: participants,
				},
			});
		}
		throw err;
	}
}

// ---------------------------------------------------------------------------
// Step 14 — Route-order edge sanity
// Per A2-β §5.1 step 14.
// ---------------------------------------------------------------------------

/**
 * Step 14: For each `RouteContribution.before` / `after` token, the
 * referenced `id` must exist among the `id`s declared by some other
 * `RouteContribution`. Unknown `id` throws `route-order-target-missing`.
 * Per A2-β §5.1 step 14.
 * @internal
 */
function checkRouteOrderEdges(rawModules: readonly Module[]): void {
	// Collect all declared route ids
	const declaredIds = new Set<string>();
	for (const m of rawModules) {
		for (const entry of m.contributes?.routes ?? []) {
			if (typeof entry === "object" && entry !== null) {
				const route = entry as RouteContribution;
				if (route.id !== undefined) {
					declaredIds.add(route.id);
				}
			}
		}
	}

	// Check all before/after references
	for (const m of rawModules) {
		for (const entry of m.contributes?.routes ?? []) {
			if (typeof entry !== "object" || entry === null) continue;
			const route = entry as RouteContribution;

			const checkRefs = (tokens: readonly string[] | undefined, direction: "before" | "after") => {
				if (!tokens) return;
				for (const token of tokens) {
					if (!declaredIds.has(token)) {
						throw new BootError({
							message: `Route order edge "${direction}: ${token}" in module "${m.name}" references an unknown id.`,
							reason: "route-order-target-missing",
							stage: "validateManifests",
							details:
								route.id !== undefined
									? {
											reason: "route-order-target-missing",
											id: token,
											referencedBy: route.id,
											direction,
										}
									: {
											reason: "route-order-target-missing",
											id: token,
											referencedBy: null,
											referencedByMountPath: route.mountPath,
											direction,
										},
						});
					}
				}
			};

			checkRefs(route.before, "before");
			checkRefs(route.after, "after");
		}
	}
}

// ---------------------------------------------------------------------------
// Public API — validateManifests
// ---------------------------------------------------------------------------

/**
 * Stage 1 of the A2-β boot planner pipeline. Accepts the consumer's
 * `Module[]`, `bootstrapComponents`, `contributionKinds`, and
 * `overrideComponents` and runs 14 ordered sub-checks.
 *
 * Returns a `ValidatedManifests` on success. Throws a typed `BootError`
 * on the first violation in input-array order.
 *
 * The stage is **deterministic and side-effect-free**: same inputs → same
 * output / same error. Per A2-β §5.1.
 */
export function validateManifests(input: ValidateManifestsInput): ValidatedManifests {
	const { modules, bootstrapComponents, contributionKinds, overrideComponents } = input;

	// Normalise all modules first for efficient lookup across checks
	const normalisedModules = modules.map(normaliseModule);

	// Step 1: Module identity uniqueness
	checkUniqueModuleNames(modules);

	// Step 2: Provides closure (no duplicate providers)
	checkProvidesClosure(normalisedModules);

	// Step 3: Bootstrap + synthetic-key disjointness
	checkBootstrapAndSyntheticDisjointness(
		normalisedModules,
		bootstrapComponents,
		overrideComponents,
	);

	// Step 4: Requires closure
	checkRequiresClosure(normalisedModules, bootstrapComponents, overrideComponents);

	// Step 5: Contribution kind coverage
	checkContributionKindCoverage(normalisedModules, contributionKinds);

	// Step 6: Per-kind name-keyed duplicate contributes
	checkPerKindContributeDuplicates(normalisedModules);

	// Step 7: Route collisions + advertisement path validation
	checkRouteCollisions(normalisedModules, modules);

	// Step 8: Override target existence
	checkOverrideTargets(normalisedModules);

	// Step 9: Duplicate override check
	checkOverrideDuplicates(normalisedModules);

	// Step 10: Same-module contribute+override collision
	checkSameModuleContributeOverride(normalisedModules);

	// Step 11: List-shaped override rejection
	checkListShapedOverrides(modules);

	// Step 12: Lifecycle/provides closure
	checkLifecycleClosure(normalisedModules);

	// Step 13: Config schema composition and validation
	validateAndComposeConfig(modules, bootstrapComponents);

	// Step 14: Route-order edge sanity
	checkRouteOrderEdges(modules);

	// Build output indices
	const validatedModules: ValidatedModule[] = normalisedModules.map((normalised, i) => ({
		manifest: modules[i],
		normalised,
	}));

	const byName = new Map<string, ValidatedModule>();
	const providers = new Map<ComponentKey, ValidatedModule>();
	const usedKindsSet = new Set<ContributionKind>();

	for (const vm of validatedModules) {
		byName.set(vm.manifest.name, vm);

		for (const key of vm.normalised.providesKeys) {
			providers.set(key, vm);
		}

		for (const entry of vm.normalised.contributesEntries) {
			usedKindsSet.add(entry.kind);
		}
		for (const entry of vm.normalised.overridesEntries) {
			usedKindsSet.add(entry.kind);
		}
	}

	return {
		modules: validatedModules,
		byName,
		providers,
		usedKinds: usedKindsSet,
	};
}
