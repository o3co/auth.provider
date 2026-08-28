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
import type { AppConfig } from "../config/application.schema.mjs";
import {
	composeConfigSchema,
	readAccessTokenRevocationMode,
} from "../config/application.schema.mjs";
import type { ComponentKey, ComponentMap } from "../modules/manifest/component-map.mjs";
import type { Module } from "../modules/manifest/module-spec.mjs";
import type { RouteContribution } from "../modules/manifest/route-contribution.mjs";
import { SYNTHETIC_COMPONENT_KEYS } from "../modules/manifest/synthetic-keys.mjs";
import { checkReplicaSafety } from "./replica-safety.mjs";
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
			// List-shaped kinds: auditHooks, routes, grantPolicyHooks, grantMiddleware
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
	"federationRedirectPolicies",
	"tokenExchangeValidators",
	"mfaFactors",
	"auditHooks",
	"routes",
	"grantPolicyHooks",
	"grantMiddleware",
	"tokenBindingMechanisms",
	"discoveryMetadata",
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
	// Build index-by-name for tie-breaking (earliest input-array position)
	const indexByName = new Map<string, number>();
	for (let i = 0; i < modules.length; i++) {
		indexByName.set(modules[i].name, i);
	}

	// Backward walk: from F, find the "root" by stepping to the earliest-
	// input-array requirer (the module whose requires is satisfied by F's
	// provides). Tie-break by lexicographically smallest name. Halt when no
	// requirer exists or visited-set hit.
	//
	// During the walk, record each step as a parent-pointer link
	// `{ child, parent, viaKey }` where `viaKey` is the lexicographically
	// smallest key in `child.requires` whose provider is `parent`. Reversing
	// the recorded links yields the forward chain rootModule → ... → F with
	// each link's `requires` key already chosen — no second forward walk is
	// needed (and no chance the walk dead-ends short of F, which was the
	// failure mode of the previous greedy reconstruction). Per multi-agent
	// review (Claude S2).
	const backwardChain: NormalisedModule[] = [failingModule];
	const linkKeys: ComponentKey[] = []; // linkKeys[i] = key of backwardChain[i+1].requires whose provider is backwardChain[i]
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
			let viaKeyForM: ComponentKey | undefined;
			for (const reqKey of m.requires) {
				const provider = providerIndex.get(reqKey);
				if (provider?.name === current.name) {
					if (viaKeyForM === undefined || reqKey < viaKeyForM) {
						viaKeyForM = reqKey;
					}
				}
			}
			if (viaKeyForM === undefined) continue;
			const idx = indexByName.get(m.name) ?? Number.MAX_SAFE_INTEGER;
			if (
				idx < bestIndex ||
				(idx === bestIndex && bestRequirer !== undefined && m.name < bestRequirer.name)
			) {
				bestIndex = idx;
				bestRequirer = m;
			}
		}

		if (bestRequirer === undefined) {
			// current is the root
			break;
		}

		// Re-derive the lex-smallest viaKey for the chosen bestRequirer (cheap;
		// avoids carrying it through the bestRequirer-selection dance).
		let viaKey: ComponentKey | undefined;
		for (const reqKey of bestRequirer.requires) {
			const provider = providerIndex.get(reqKey);
			if (provider?.name === current.name) {
				if (viaKey === undefined || reqKey < viaKey) {
					viaKey = reqKey;
				}
			}
		}

		visited.add(bestRequirer.name);
		backwardChain.push(bestRequirer);
		// viaKey is guaranteed non-undefined: bestRequirer was selected because
		// some key of its requires has provider === current. The biome-ignore
		// reflects that invariant.
		// biome-ignore lint/style/noNonNullAssertion: bestRequirer-selection guarantees viaKey is defined
		linkKeys.push(viaKey!);
		current = bestRequirer;
	}

	const rootModule = current;

	// Forward path: reverse backwardChain to get [rootModule, ..., failingModule],
	// reverse linkKeys correspondingly. Each link i in the forward chain becomes
	// `{ module: forwardChain[i].name, requires: forwardLinkKeys[i], satisfiedBy: forwardChain[i + 1].name }`.
	const forwardChain = [...backwardChain].reverse();
	const forwardLinkKeys = [...linkKeys].reverse();

	const path: { module: string; requires: ComponentKey; satisfiedBy?: string }[] = [];
	for (let i = 0; i < forwardChain.length - 1; i++) {
		path.push({
			module: forwardChain[i].name,
			// biome-ignore lint/style/noNonNullAssertion: forwardLinkKeys.length === forwardChain.length - 1
			requires: forwardLinkKeys[i]!,
			satisfiedBy: forwardChain[i + 1].name,
		});
	}

	// Terminal link: the failing module with the missing key (no satisfiedBy)
	path.push({ module: failingModule.name, requires: missingKey });

	return { rootModule: rootModule.name, path };
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
 *
 * Dispatches on `collector.kind === "name-keyed"` rather than a hardcoded
 * built-in name set, so consumer-defined name-keyed kinds (added via
 * declare-module augmentation of ContributionCollectorMap) are also
 * duplicate-checked. Mirrors the Task 6 fixup applied in
 * apply-contributions.mts (commit 4d03cc0b).
 *
 * Per A2-β §5.1 step 6.
 * @internal
 */
function checkPerKindContributeDuplicates(
	modules: readonly NormalisedModule[],
	contributionKinds: ContributionKindMap,
): void {
	// Track (kind, name) → first contributing module
	const seen = new Map<string, string>(); // key: `${kind}:${name}`

	for (const m of modules) {
		for (const entry of m.contributesEntries) {
			const kind = entry.kind;
			// Look up the collector for this kind; only name-keyed collectors
			// participate in the (kind, name) duplicate check.
			const collector = (contributionKinds as Record<string, unknown>)[kind] as
				| { kind?: string }
				| undefined;
			if (collector?.kind !== "name-keyed") continue;
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
// Step 7.5 — Federation / federationRedirectPolicies pairing invariant
// Per A5 §8.2.
// ---------------------------------------------------------------------------

/**
 * Step 7.5: Every `federations[name]` contribution MUST have a matching
 * `federationRedirectPolicies[name]` contribution and vice versa.
 *
 * Throws BootError({ reason: "federation-redirect-policy-unpaired" }).
 * Per A5 §8.2.
 * @internal
 */
function checkFederationRedirectPolicyPairing(modules: readonly NormalisedModule[]): void {
	const federationNames = new Map<string, string>(); // name → first contributing module
	const policyNames = new Map<string, string>(); // name → first contributing module

	// Inspect both contributes and overrides: a name is considered "registered"
	// for pairing-invariant purposes if EITHER side declares it (per spec §8.2
	// intent — "policy is registered for this name from somewhere"). Walking
	// only contributesEntries would mis-diagnose the case where Module A
	// contributes federations[google] and Module B overrides
	// federationRedirectPolicies[google]: pairing would fire
	// "federation-without-policy" for google before step 8 (override-target-
	// missing) could surface the more precise "override has no contribute
	// target" error.
	for (const m of modules) {
		const allEntries = [...m.contributesEntries, ...m.overridesEntries];
		for (const entry of allEntries) {
			if (entry.kind === "federations" && typeof entry.key === "string") {
				if (!federationNames.has(entry.key)) {
					federationNames.set(entry.key, m.name);
				}
			} else if (entry.kind === "federationRedirectPolicies" && typeof entry.key === "string") {
				if (!policyNames.has(entry.key)) {
					policyNames.set(entry.key, m.name);
				}
			}
		}
	}

	for (const [name, contributedBy] of federationNames) {
		if (!policyNames.has(name)) {
			throw new BootError({
				message: `Federation "${name}" (contributed by "${contributedBy}") has no matching federationRedirectPolicies["${name}"] contribution.`,
				reason: "federation-redirect-policy-unpaired",
				stage: "validateManifests",
				details: {
					reason: "federation-redirect-policy-unpaired",
					name,
					side: "federation-without-policy",
					contributedBy,
				},
			});
		}
	}

	for (const [name, contributedBy] of policyNames) {
		if (!federationNames.has(name)) {
			throw new BootError({
				message: `federationRedirectPolicies["${name}"] (contributed by "${contributedBy}") has no matching federations["${name}"] contribution.`,
				reason: "federation-redirect-policy-unpaired",
				stage: "validateManifests",
				details: {
					reason: "federation-redirect-policy-unpaired",
					name,
					side: "policy-without-federation",
					contributedBy,
				},
			});
		}
	}
}

// ---------------------------------------------------------------------------
// Step 13.5 — CP-20 grantPolicy / jwt.issuer consistency invariant
//
// Restores the v0.4.x guard. When `grantPolicy` is wired through ANY of the
// three supported component sources — module `provides`, `bootstrapComponents`,
// or `overrideComponents` — the configured issuer must be a non-empty string.
// The policy hook signs decisions against that issuer; an empty value silently
// disables CP-18 fail-closed enforcement at the JWT layer. Runs after step 13
// (validateAndComposeConfig) so the parsed config is available.
// ---------------------------------------------------------------------------

function checkGrantPolicyIssuerInvariant(
	modules: readonly NormalisedModule[],
	parsedConfig: unknown,
	bootstrapComponents: BootstrapMap,
	overrideComponents: Partial<ComponentMap> | undefined,
): void {
	// Resolve the wiring source in priority: module provides → override →
	// bootstrap. The detail's `providedBy` field reports the first source
	// found; step 2 (checkProvidesClosure) guarantees module-side uniqueness,
	// and the bootstrap/override sentinels are deliberately distinct strings
	// so downstream tooling can tell them apart.
	const moduleProvider = modules.find((m) =>
		(m.providesKeys as readonly string[]).includes("grantPolicy"),
	);
	const overrideHasGrantPolicy =
		overrideComponents !== undefined &&
		(overrideComponents as Record<string, unknown>).grantPolicy !== undefined;
	const bootstrapHasGrantPolicy =
		(bootstrapComponents as Record<string, unknown>).grantPolicy !== undefined;

	let providedBy: string | undefined;
	if (moduleProvider) providedBy = moduleProvider.name;
	else if (overrideHasGrantPolicy) providedBy = "<overrideComponents>";
	else if (bootstrapHasGrantPolicy) providedBy = "<bootstrapComponents>";

	if (providedBy === undefined) return;

	const issuer = (parsedConfig as { oauth?: { jwt?: { issuer?: unknown } } } | undefined)?.oauth
		?.jwt?.issuer;
	if (typeof issuer === "string" && issuer.length > 0) return;

	throw new BootError({
		message: `CP-20 invariant: config.oauth.jwt.issuer must be a non-empty string when grantPolicy is wired (provided by "${providedBy}"). Empty issuer turns CP-18 fail-closed enforcement into silent allow-all at the JWT layer.`,
		reason: "grant-policy-without-issuer",
		stage: "validateManifests",
		details: {
			reason: "grant-policy-without-issuer",
			providedBy,
		},
	});
}

// ---------------------------------------------------------------------------
// Step 13.6 — MFA partial-wiring guard
// Per issue #101, A2-β §6.1 amendment 2026-05.
// ---------------------------------------------------------------------------

/**
 * If `mfaCoordinator` is provided by any module, both `mfaProviderFactory`
 * and `mfaTransactionStore` MUST also be provided. Otherwise the first MFA
 * flow crashes at runtime with a confusing `Cannot read properties of
 * undefined`.
 *
 * Per issue #101, A2-β amendment 2026-05.
 */
export function checkMfaPartialWiring(plannedKeys: ReadonlySet<string>): void {
	if (!plannedKeys.has("mfaCoordinator")) return;
	const missing: ("mfaProviderFactory" | "mfaTransactionStore")[] = [];
	if (!plannedKeys.has("mfaProviderFactory")) missing.push("mfaProviderFactory");
	if (!plannedKeys.has("mfaTransactionStore")) missing.push("mfaTransactionStore");
	if (missing.length > 0) {
		throw new BootError({
			stage: "validateManifests",
			reason: "mfa-partial-wiring",
			message: `mfaCoordinator is provided but ${missing.join(" and ")} ${missing.length === 1 ? "is" : "are"} missing`,
			details: { reason: "mfa-partial-wiring", missing },
		});
	}
}

// ---------------------------------------------------------------------------
// Step 13.7 — Federation stores wiring guard
// Per issue #101 TODO-F-1, A2-β §6.1 amendment 2026-05.
// ---------------------------------------------------------------------------

const FEDERATION_REQUIRED_STORES = [
	"userSessionStore",
	"sessionRPRegistry",
	"sessionFamilyIndex",
	"sessionFederationIndex",
	"federationTokenStore",
	"refreshTokenFamilyRevocation",
] as const;

/**
 * If any `config.federations.<name>.enabled === true`, all 6 session/
 * federation/refresh-token-family slots MUST be present in the planned
 * component set. A missing store causes federation routes either to 503 at
 * runtime with an opaque error (session/federationToken stores) or to never
 * mount at all (refreshTokenFamilyRevocation — see packages/oauth/src/routes.mts
 * `logoutSupported` / `federationTokenSupported` gates), surfacing as
 * unexpected 404s. Both failure modes are equally opaque from the operator's
 * perspective; the validator surfaces them at boot time.
 *
 * Per issue #101 TODO-F-1, A2-β §6.1 amendment 2026-05; refreshTokenFamilyRevocation
 * gating added per #103 review (alignment with route-level gating in oauth/routes.mts).
 */
export function checkFederationStoresWiring(
	config: AppConfig,
	plannedKeys: ReadonlySet<string>,
): void {
	const federations = (config.federations ?? {}) as Record<string, { enabled?: boolean }>;
	for (const [name, fed] of Object.entries(federations)) {
		if (fed?.enabled !== true) continue;
		const missing = FEDERATION_REQUIRED_STORES.filter((k) => !plannedKeys.has(k));
		if (missing.length > 0) {
			throw new BootError({
				stage: "validateManifests",
				reason: "federation-stores-incomplete",
				message: `federations.${name} is enabled but required federation stores are missing: ${missing.join(", ")}`,
				details: { reason: "federation-stores-incomplete", federationName: name, missing },
			});
		}
	}
}

// ---------------------------------------------------------------------------
// Step 13.9 — Access-token revocation enforceability guard
// Per issue #277.
// ---------------------------------------------------------------------------

/**
 * `POST /oauth/revoke` MUST answer 200 for a well-formed request (RFC 7009
 * §2.2), which makes the 200 the operator's only signal that anything
 * happened. For access tokens the thing that happens is `accessTokenDenylist.add`;
 * with no denylist wired the endpoint verified the token, logged a warning
 * nobody reads mid-incident, and returned the same 200 while the JWT kept
 * working everywhere until expiry.
 *
 * So: when this composition reads the `accessTokenDenylist` slot and
 * `oauth.revocation.accessToken` is `"denylist"` — or absent, which this check
 * reads the same way (`readAccessTokenRevocationMode` deliberately defaults
 * nothing; see its JSDoc) — the slot must be filled. Otherwise boot fails.
 *
 * **The trigger is slot consumption, not the route table.** Core cannot see
 * that `packages/oauth` mounts `/oauth/revoke`: oauth contributes its routes as
 * a factory, and step 7 can only inspect statically-declared
 * `RouteContribution` values — a factory's mount paths do not exist until
 * `applyContributions` runs it. A module declaring `accessTokenDenylist`
 * in `requires` / `optional` is the composition-level statement that
 * denylist-backed access-token revocation is part of this app's surface, and it
 * is observable here, at stage 1, before a single component is constructed.
 * The approximation errs toward asking: a module that reads the slot for some
 * other purpose still gets told to wire one or to declare the capability
 * absent, and both answers are cheap.
 *
 * Deployments that genuinely do not revoke access tokens say so —
 * `oauth.revocation.accessToken = "unsupported"` — and the endpoint then
 * answers `unsupported_token_type` instead of a hollow 200.
 *
 * **Refresh-token revocation is out of scope in both modes.** It runs off
 * `refreshTokenFamilyRevocation` and never needed a denylist; this guard must
 * not be read as requiring one for `/oauth/revoke` as a whole.
 */
export function checkAccessTokenRevocationWiring(
	modules: readonly NormalisedModule[],
	config: unknown,
	plannedKeys: ReadonlySet<string>,
): void {
	// Omission means `"denylist"` here — see `readAccessTokenRevocationMode`.
	// Only an explicit `"unsupported"` excuses the missing slot.
	if (readAccessTokenRevocationMode(config) === "unsupported") return;
	if (plannedKeys.has("accessTokenDenylist")) return;

	const consumedBy = modules
		.filter(
			(m) =>
				(m.requires as readonly string[]).includes("accessTokenDenylist") ||
				(m.optional as readonly string[]).includes("accessTokenDenylist"),
		)
		.map((m) => m.name);
	if (consumedBy.length === 0) return;

	throw new BootError({
		stage: "validateManifests",
		reason: "access-token-revocation-unenforceable",
		message:
			`oauth.revocation.accessToken is "denylist" (the reading when the key is absent) and ${consumedBy.length === 1 ? `module "${consumedBy[0]}" reads` : `modules [${consumedBy.join(", ")}] read`} ` +
			"the accessTokenDenylist slot, but nothing provides one. RFC 7009 revocation of an access " +
			"token would answer 200 and leave the token valid until it expires. Wire a denylist " +
			'(a shared one — `accessTokenDenylist.adapter = "redis"` in the standalone template; the ' +
			"bundled memoryAccessTokenDenylistModule is single-replica only), or set " +
			'`oauth.revocation.accessToken = "unsupported"` to have the endpoint reject access-token ' +
			"revocation with unsupported_token_type. Refresh-token revocation needs no denylist and is " +
			"unaffected either way.",
		details: { reason: "access-token-revocation-unenforceable", consumedBy },
	});
}

// ---------------------------------------------------------------------------
// Step 13.10 — Declared-absence guard
// Per issue #363. (#368 tracks turning these numbered guards into a registry.)
// ---------------------------------------------------------------------------

/** Read a dotted path off the parsed config without asserting its shape. */
function readConfigPath(config: unknown, path: readonly string[]): unknown {
	let value: unknown = config;
	for (const segment of path) {
		if (value === null || typeof value !== "object") return undefined;
		value = (value as Record<string, unknown>)[segment];
	}
	return value;
}

/**
 * Generic enforcement for `ModuleSpec.absencePolicies` (#363): every optional
 * key carrying a policy must be filled from one of the three component
 * sources, or the config must carry the policy's declared-absent value.
 * Otherwise boot refuses with `component-absence-undeclared` — the capability
 * slot cannot be a silent no-op, which is the failure mode #277 (revocation),
 * #287 (audit sink) and #322 (subject revocation) all shipped.
 *
 * Two modules attaching *different* policies to the same key is refused
 * outright, even when the absence is declared: the boot error's advice must
 * not depend on module input order, and the bundled modules share one policy
 * constant per key (e.g. `AUDIT_SINK_ABSENCE_POLICY`) precisely so this
 * cannot happen by accident.
 *
 * `consumedBy` follows `checkAccessTokenRevocationWiring`'s reading: every
 * module naming the key in `requires` / `optional` is the evidence that the
 * slot is part of this app's surface. That check (#277, step 13.9) predates
 * this vocabulary and keeps its spec-pinned reason; new absence rules attach
 * an `AbsencePolicy` instead of adding another bespoke stage.
 */
function checkDeclaredAbsence(
	modules: readonly NormalisedModule[],
	rawModules: readonly Module[],
	config: unknown,
	plannedKeys: ReadonlySet<string>,
): void {
	interface Collected {
		readonly policy: {
			readonly configKey: readonly string[];
			readonly absentValue: string;
			readonly hint: string;
		};
		readonly declaredBy: string[];
	}
	const byKey = new Map<string, Collected>();

	for (const m of rawModules) {
		for (const [key, policy] of Object.entries(m.absencePolicies ?? {})) {
			if (policy === undefined) continue;
			const existing = byKey.get(key);
			if (existing === undefined) {
				byKey.set(key, { policy, declaredBy: [m.name] });
				continue;
			}
			const agrees =
				existing.policy.absentValue === policy.absentValue &&
				existing.policy.configKey.length === policy.configKey.length &&
				existing.policy.configKey.every((seg, i) => seg === policy.configKey[i]);
			if (!agrees) {
				throw new BootError({
					message:
						`Absence policies for "${key}" disagree — modules ` +
						`[${[...existing.declaredBy, m.name].join(", ")}] declare different ` +
						"config keys or absent values for the same slot, so the boot error's " +
						"advice would depend on module order. Share one policy constant.",
					reason: "component-absence-undeclared",
					stage: "validateManifests",
					details: {
						reason: "component-absence-undeclared",
						componentKey: key as ComponentKey,
						consumedBy: [...existing.declaredBy, m.name],
						configKey: existing.policy.configKey.join("."),
						absentValue: existing.policy.absentValue,
					},
				});
			}
			existing.declaredBy.push(m.name);
		}
	}

	for (const [key, { policy }] of byKey) {
		if (plannedKeys.has(key)) continue;
		if (readConfigPath(config, policy.configKey) === policy.absentValue) continue;

		const consumedBy = modules
			.filter(
				(m) =>
					(m.requires as readonly string[]).includes(key) ||
					(m.optional as readonly string[]).includes(key),
			)
			.map((m) => m.name);
		const configKeyDotted = policy.configKey.join(".");

		throw new BootError({
			message:
				`Component "${key}" is read by ` +
				`${consumedBy.length === 1 ? `module "${consumedBy[0]}"` : `modules [${consumedBy.join(", ")}]`} ` +
				"but nothing provides it, and its absence is not declared. " +
				`Wire a provider, or set ${configKeyDotted} = "${policy.absentValue}" to declare ` +
				`the capability absent on purpose. ${policy.hint}`,
			reason: "component-absence-undeclared",
			stage: "validateManifests",
			details: {
				reason: "component-absence-undeclared",
				componentKey: key as ComponentKey,
				consumedBy,
				configKey: configKeyDotted,
				absentValue: policy.absentValue,
			},
		});
	}
}

// ---------------------------------------------------------------------------
// Step 8 — Override target existence
// Per A2-β §5.1 step 8.
// ---------------------------------------------------------------------------

/**
 * Step 8: Every `overrides[kind][name]` must have a matching target. The
 * target is satisfied by EITHER:
 *   1. some module's `contributes[kind][name]`, OR
 *   2. an entry pre-seeded in the consumer-supplied name-keyed collector
 *      (`contributionKinds[kind].get(name) !== undefined`).
 *
 * Carve-out (2) keeps validate-stage and apply-stage in agreement: §5.4
 * step 2 routes overrides through `collector.replace(name, value)`, which
 * succeeds whenever the collector already has an entry for `name` —
 * regardless of whether that entry came from a module or from a host-
 * supplied pre-seeded collector. Without this carve-out, the documented
 * "consumer extension via pre-loaded collector" path is rejected at
 * validate-stage and would never reach apply-stage. Per multi-agent
 * review (Codex P2).
 *
 * Per A2-β §5.1 step 8.
 * @internal
 */
function checkOverrideTargets(
	modules: readonly NormalisedModule[],
	contributionKinds: ContributionKindMap,
): void {
	// Build set of all contributes (kind, name) pairs across modules.
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
			if (contributed.has(compoundKey)) continue;

			// Fallback: consumer-seeded name-keyed collector with a pre-existing
			// entry under this name is also a valid override target.
			const collector = (contributionKinds as Record<string, unknown>)[entry.kind] as
				| { kind: string; get?: (name: string) => unknown }
				| undefined;
			if (collector?.kind === "name-keyed" && collector.get?.(entry.key) !== undefined) {
				continue;
			}

			throw new BootError({
				message: `Override target missing — module "${m.name}" overrides "${entry.kind}.${entry.key}" but no module contributes it and no consumer-seeded collector pre-loaded it.`,
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
 * Step 11: A module's `overrides` carrying any list-shaped kind throws
 * `list-shaped-override-not-allowed`.
 *
 * Dispatches on `collector.kind === "list" | "list-routes"` so consumer-
 * defined list-shaped kinds are also caught. Mirrors the Task 6 fixup
 * applied in apply-contributions.mts (commit 4d03cc0b). The built-in
 * list-shaped kinds (routes, auditHooks, grantPolicyHooks, grantMiddleware)
 * match by collector identity; consumer-defined kinds with list-shaped
 * collectors match the same way.
 *
 * The `details.kind` literal is typed as the built-in union
 * `"routes" | "auditHooks" | "grantPolicyHooks" | "grantMiddleware"` per
 * spec §6.1 `ListShapedOverrideDetails`; a consumer-defined kind name is
 * widened via cast since the Details type does not yet model consumer
 * extensions.
 *
 * Per A2-β §5.1 step 11.
 * @internal
 */
function checkListShapedOverrides(
	rawModules: readonly Module[],
	contributionKinds: ContributionKindMap,
): void {
	for (const m of rawModules) {
		const overrides = m.overrides ?? {};
		for (const kind of Object.keys(overrides)) {
			const collector = (contributionKinds as Record<string, unknown>)[kind] as
				| { kind?: string }
				| undefined;
			if (collector?.kind !== "list" && collector?.kind !== "list-routes") continue;
			throw new BootError({
				message: `Module "${m.name}" attempts to override list-shaped kind "${kind}", which is not allowed.`,
				reason: "list-shaped-override-not-allowed",
				stage: "validateManifests",
				details: {
					reason: "list-shaped-override-not-allowed",
					kind: kind as
						| "routes"
						| "auditHooks"
						| "grantPolicyHooks"
						| "grantMiddleware"
						| "tokenBindingMechanisms",
					module: m.name,
				},
			});
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
 * Returns the parsed config value (with Zod defaults / transforms applied)
 * so the caller can substitute it back into bootstrapComponents.
 * On parse failure throws `config-validation-failed`.
 * Per A2-β §5.1 step 13.
 * @internal
 */
function validateAndComposeConfig(modules: readonly Module[], bootstrap: BootstrapMap): unknown {
	const schemas: z.ZodObject<z.ZodRawShape>[] = [];
	const participants: { readonly module: string; readonly schemaPath?: string }[] = [];

	for (const m of modules) {
		if (m.configSchema) {
			schemas.push(m.configSchema);
			participants.push({ module: m.name });
		}
	}

	// Always run composeConfigSchema — it always includes CoreConfigSchema as
	// the base, even when no module declares a configSchema. Skipping the
	// parse when `schemas.length === 0` would let an invalid `oauth` / `http`
	// section through and deny module-less consumers the CoreConfigSchema
	// defaults that downstream code (and the bootstrap.config slot type)
	// assumes are present.
	const composedSchema = composeConfigSchema(schemas);

	try {
		const rawConfig = (bootstrap as Record<string, unknown>).config;
		const parsed = composedSchema.parse(rawConfig) as Record<string, unknown>;
		// CoreConfigSchema's top-level z.object strips unknown keys. When no
		// module declares a configSchema, extras like `session`, `repositories`,
		// `rateLimit`, `cors`, and consumer-specific top-level keys would be
		// silently dropped — incompatible with `ComponentMap.config: AppConfig`
		// (the typed slot promises a fuller shape than CoreConfig). Merge the
		// parsed result over the raw input: parsed values win at every key the
		// schema knows about (so Zod defaults apply); raw extras at the top
		// level are preserved untouched. Per Codex P2 finding on the prior
		// hardening commit (270914f5).
		const rawObj =
			rawConfig !== null && typeof rawConfig === "object"
				? (rawConfig as Record<string, unknown>)
				: {};
		return { ...rawObj, ...parsed };
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
 * `RouteContribution`.
 *
 * Factory-shaped routes (`(deps) => RouteContribution`) produce their `id`
 * at materialise time, so their ids are opaque at validate-stage. When at
 * least one module declares a function-shaped routes entry anywhere,
 * unknown refs are deferred to assembleApp's mount-order pass (§5.6
 * step 1), which sees the full materialised id set. This carve-out keeps
 * the documented mixed static/factory route ordering scenario reachable.
 * Per multi-agent review (Codex P2).
 *
 * Pure-static apps (no factory route entries anywhere) get the typo-catch
 * benefit of the early check.
 *
 * Per A2-β §5.1 step 14.
 * @internal
 */
function checkRouteOrderEdges(rawModules: readonly Module[]): void {
	// Detect any factory-shaped routes entries across all modules. A single
	// factory route anywhere defers all unknown-ref checks to assembleApp.
	let anyFactoryRouteEntry = false;
	for (const m of rawModules) {
		for (const entry of m.contributes?.routes ?? []) {
			if (typeof entry === "function") {
				anyFactoryRouteEntry = true;
				break;
			}
		}
		if (anyFactoryRouteEntry) break;
	}
	if (anyFactoryRouteEntry) return;

	// Collect all declared route ids (pure-static path)
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
	checkPerKindContributeDuplicates(normalisedModules, contributionKinds ?? {});

	// Step 7: Route collisions + advertisement path validation
	checkRouteCollisions(normalisedModules, modules);

	// Step 7.5: Federation / federationRedirectPolicies pairing invariant
	checkFederationRedirectPolicyPairing(normalisedModules);

	// Step 8: Override target existence
	checkOverrideTargets(normalisedModules, contributionKinds ?? {});

	// Step 9: Duplicate override check
	checkOverrideDuplicates(normalisedModules);

	// Step 10: Same-module contribute+override collision
	checkSameModuleContributeOverride(normalisedModules);

	// Step 11: List-shaped override rejection
	checkListShapedOverrides(modules, contributionKinds ?? {});

	// Step 12: Lifecycle/provides closure
	checkLifecycleClosure(normalisedModules);

	// Step 13: Config schema composition and validation.
	// The parsed value (with Zod defaults / transforms applied) replaces the
	// original config in the returned bootstrapComponents so all downstream
	// stages receive the fully-validated config. Per A2-β §5.1 step 13.
	const parsedConfig = validateAndComposeConfig(modules, bootstrapComponents);
	const substitutedBootstrap: BootstrapMap = {
		...bootstrapComponents,
		config: parsedConfig as BootstrapMap["config"],
	};

	// Step 13.5: CP-20 grantPolicy/issuer invariant — runs after step 13 so
	// the parsed config is available (restored v0.4.x guard). Inspects all
	// three supported component sources: module provides, bootstrapComponents,
	// and overrideComponents.
	checkGrantPolicyIssuerInvariant(
		normalisedModules,
		parsedConfig,
		bootstrapComponents,
		overrideComponents,
	);

	// Step 13.6: MFA partial-wiring guard — if mfaCoordinator is provided,
	// both mfaProviderFactory and mfaTransactionStore MUST also be provided.
	// Per issue #101, A2-β §6.1 amendment 2026-05.
	//
	// `plannedKeys` MUST cover all three supported component sources (module
	// provides, bootstrapComponents, overrideComponents) — same shape as the
	// CP-20 invariant at step 13.5. Otherwise a composition root that wires
	// MFA / federation stores via bootstrap or override is falsely rejected
	// (see multi-agent-review I1+P2 convergence, 2026-05-01).
	{
		const plannedKeys = new Set<string>([
			...normalisedModules.flatMap((m) => m.providesKeys as string[]),
			...Object.keys(bootstrapComponents),
			...Object.keys(overrideComponents ?? {}),
		]);
		checkMfaPartialWiring(plannedKeys);

		// Step 13.7: Federation stores wiring guard — if any federation is
		// enabled in config, all required federation stores must be wired
		// (see FEDERATION_REQUIRED_STORES for the authoritative list).
		// Per issue #101 TODO-F-1, A2-β §6.1 amendment 2026-05.
		checkFederationStoresWiring(parsedConfig as AppConfig, plannedKeys);

		// Step 13.9: access-token revocation enforceability — a composition that
		// reads the `accessTokenDenylist` slot must have one, unless it declares
		// `oauth.revocation.accessToken = "unsupported"`. Per issue #277.
		checkAccessTokenRevocationWiring(normalisedModules, parsedConfig, plannedKeys);

		// Step 13.10: declared-absence guard — every optional key carrying an
		// AbsencePolicy must be filled or declared absent in config. The
		// generic form of 13.9's pattern. Per issue #363.
		checkDeclaredAbsence(normalisedModules, modules, parsedConfig, plannedKeys);
	}

	// Step 13.8: Replica-safety guard — state held in this process's memory
	// that a multi-replica deployment must share. Fails boot when
	// `deployment.mode = "multi"`, warns when the mode is unset, silent when
	// the operator declared `"single"`. Per issue #271.
	//
	// The logger comes from `bootstrapComponents` rather than a new parameter:
	// a composition root that configured one has already put it there, and the
	// warning is worthless if it goes somewhere the operator is not reading.
	{
		const bootLogger = bootstrapComponents.logger;
		checkReplicaSafety({
			modules: normalisedModules,
			config: parsedConfig,
			...(bootLogger !== undefined ? { logger: bootLogger } : {}),
		});
	}

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
		bootstrapComponents: substitutedBootstrap,
	};
}
