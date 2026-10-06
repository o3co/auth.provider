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
 * boot/plan-boot.mts: stage 2 of the boot planner. Turns `ValidatedManifests`
 * into a `BootPlan` (dependency graph, cycle detection, init order and the
 * per-component activation closure); see `planBoot` for the steps.
 */

import type { ComponentKey, ComponentMap } from "../modules/manifest/component-map.mjs";
import type {
	ActivationSeed,
	BootPlan,
	BootstrapMap,
	DepsBlueprint,
	NormalisedModule,
	ProviderActivation,
	ValidatedManifests,
	ValidatedModule,
} from "./types.mjs";
import { BootError } from "./types.mjs";

// ---------------------------------------------------------------------------
// Step 1 — Build dependency graph
// ---------------------------------------------------------------------------

/**
 * Adjacency-list dependency graph: an edge A → B means A requires a component
 * key B provides. Bootstrap and override keys are virtual providers, and the
 * requirements they satisfy produce no edges.
 * @internal
 */
interface DependencyGraph {
	/** All module names (nodes), in input declaration order. */
	readonly nodeOrder: readonly string[];
	/**
	 * For each module, the modules it depends on: edges from `requires`, and
	 * from `optional` only when another module (not bootstrap/override)
	 * provides the key.
	 */
	readonly adj: ReadonlyMap<string, ReadonlySet<string>>;
	/** Reverse adjacency: for each module, who depends on it. */
	readonly radj: ReadonlyMap<string, ReadonlySet<string>>;
}

/**
 * Builds the dependency graph; `virtualKeys` are the bootstrap and override
 * keys.
 * @internal
 */
function buildDependencyGraph(
	validated: ValidatedManifests,
	virtualKeys: ReadonlySet<ComponentKey>,
): DependencyGraph {
	const nodeOrder = validated.modules.map((vm) => vm.manifest.name);

	const adj = new Map<string, Set<string>>();
	const radj = new Map<string, Set<string>>();
	for (const name of nodeOrder) {
		adj.set(name, new Set());
		radj.set(name, new Set());
	}

	const providers = validated.providers;

	/**
	 * Adds an edge from the requiring module to the providing one. Self-edges
	 * are kept so cycle detection reports a module that depends on itself.
	 */
	function addEdge(from: string, to: string): void {
		// biome-ignore lint/style/noNonNullAssertion: nodeOrder is built from validated.modules, adj and radj entries are pre-seeded
		adj.get(from)!.add(to);
		// biome-ignore lint/style/noNonNullAssertion: same invariant
		radj.get(to)!.add(from);
	}

	for (const vm of validated.modules) {
		const norm = vm.normalised;
		// Mandatory requires — add edge unless satisfied by a virtual key
		for (const key of norm.requires) {
			if (virtualKeys.has(key)) continue;
			const provider = providers.get(key);
			if (provider) {
				addEdge(norm.name, provider.manifest.name);
			}
		}
		// Optional — advisory: add edge only when a module (not virtual) provides it
		for (const key of norm.optional) {
			if (virtualKeys.has(key)) continue;
			const provider = providers.get(key);
			if (provider) {
				addEdge(norm.name, provider.manifest.name);
			}
		}
	}

	return { nodeOrder, adj, radj };
}

// ---------------------------------------------------------------------------
// Step 2 — Cycle detection via Tarjan's SCC algorithm
// ---------------------------------------------------------------------------

/**
 * Tarjan's strongly-connected-components algorithm; each SCC is a list of
 * module names. Non-trivial SCCs (size > 1) and self-loops are the cycles.
 * @internal
 */
function tarjanSCC(
	nodeOrder: readonly string[],
	adj: ReadonlyMap<string, ReadonlySet<string>>,
): readonly (readonly string[])[] {
	const index = new Map<string, number>();
	const lowlink = new Map<string, number>();
	const onStack = new Set<string>();
	const stack: string[] = [];
	const sccs: string[][] = [];
	let counter = 0;

	function strongconnect(v: string): void {
		index.set(v, counter);
		lowlink.set(v, counter);
		counter++;
		stack.push(v);
		onStack.add(v);

		for (const w of adj.get(v) ?? []) {
			if (!index.has(w)) {
				strongconnect(w);
				// biome-ignore lint/style/noNonNullAssertion: w was just set in the recursive call
				lowlink.set(v, Math.min(lowlink.get(v)!, lowlink.get(w)!));
			} else if (onStack.has(w)) {
				// biome-ignore lint/style/noNonNullAssertion: w was indexed before
				lowlink.set(v, Math.min(lowlink.get(v)!, index.get(w)!));
			}
		}

		// If v is a root node, pop the SCC
		if (lowlink.get(v) === index.get(v)) {
			const scc: string[] = [];
			let w: string;
			do {
				// biome-ignore lint/style/noNonNullAssertion: stack is non-empty while v is on it
				w = stack.pop()!;
				onStack.delete(w);
				scc.push(w);
			} while (w !== v);
			sccs.push(scc);
		}
	}

	// Visit nodes in declaration order for deterministic output
	for (const node of nodeOrder) {
		if (!index.has(node)) {
			strongconnect(node);
		}
	}

	return sccs;
}

/**
 * Rebuilds a non-trivial SCC as the chain `CircularDependencyDetails.cycle`
 * carries: `{ module, requires, satisfiedBy }[]`, "A requires key X
 * (provided by B)".
 * @internal
 */
function buildCycleChain(
	scc: readonly string[],
	validated: ValidatedManifests,
): readonly {
	readonly module: string;
	readonly requires: ComponentKey;
	readonly satisfiedBy: string;
}[] {
	const sccSet = new Set(scc);
	// Build a directed path within the SCC; start from the earliest-indexed node.
	const indexByName = new Map<string, number>();
	for (let i = 0; i < validated.modules.length; i++) {
		indexByName.set(validated.modules[i].manifest.name, i);
	}

	// Pick starting node — smallest declaration index in the SCC.
	// `scc` names came from `validated.modules`, so `indexByName.get(...)` is
	// always defined here; the `!` reflects that invariant.
	let start = scc[0];
	for (const name of scc) {
		// biome-ignore lint/style/noNonNullAssertion: indexByName covers every validated module
		if (indexByName.get(name)! < indexByName.get(start)!) {
			start = name;
		}
	}

	// Walk a Hamiltonian path through the SCC following requires edges that stay
	// inside the SCC, building (module → requires → satisfiedBy) triples.
	const chain: { module: string; requires: ComponentKey; satisfiedBy: string }[] = [];
	const visited = new Set<string>();
	let current = start;

	while (true) {
		visited.add(current);
		const norm = validated.byName.get(current)?.normalised;
		if (!norm) break;

		// Find a requires key whose provider is in the SCC and unvisited (or back to start to close the cycle)
		let foundKey: ComponentKey | undefined;
		let foundNext: string | undefined;

		for (const key of norm.requires) {
			const provider = validated.providers.get(key);
			if (!provider) continue;
			const providerName = provider.manifest.name;
			if (!sccSet.has(providerName)) continue;
			if (!visited.has(providerName) || providerName === start) {
				// Prefer the unvisited next step; once all visited, close to start
				if (!visited.has(providerName)) {
					foundKey = key;
					foundNext = providerName;
					break;
				} else if (providerName === start && visited.size === scc.length) {
					foundKey = key;
					foundNext = providerName;
				}
			}
		}

		if (foundKey !== undefined && foundNext !== undefined) {
			chain.push({ module: current, requires: foundKey, satisfiedBy: foundNext });
			if (foundNext === start && visited.size === scc.length) {
				break; // cycle closed
			}
			current = foundNext;
		} else {
			break;
		}
	}

	return chain;
}

/**
 * Throws `BootError` `reason: "circular-dependency"` on a non-trivial SCC or
 * a self-loop.
 * @internal
 */
function detectCycles(graph: DependencyGraph, validated: ValidatedManifests): void {
	// Check for self-loops first (a module that depends on itself)
	for (const [node, deps] of graph.adj) {
		if (deps.has(node)) {
			const norm = validated.byName.get(node)?.normalised;
			// Find the self-requiring key
			const selfKey =
				norm?.requires.find((k) => {
					const p = validated.providers.get(k);
					return p?.manifest.name === node;
				}) ??
				norm?.optional.find((k) => {
					const p = validated.providers.get(k);
					return p?.manifest.name === node;
				});
			const requiresKey = selfKey ?? ("(self)" as ComponentKey);
			throw new BootError({
				message: `Circular dependency detected: module "${node}" depends on itself.`,
				reason: "circular-dependency",
				stage: "planBoot",
				details: {
					reason: "circular-dependency",
					cycle: [{ module: node, requires: requiresKey, satisfiedBy: node }],
				},
			});
		}
	}

	const sccs = tarjanSCC(graph.nodeOrder, graph.adj);
	for (const scc of sccs) {
		if (scc.length > 1) {
			const cycle = buildCycleChain(scc, validated);
			const names = scc.join(", ");
			throw new BootError({
				message: `Circular dependency detected among modules: [${names}].`,
				reason: "circular-dependency",
				stage: "planBoot",
				details: {
					reason: "circular-dependency",
					cycle,
				},
			});
		}
	}
}

// ---------------------------------------------------------------------------
// Step 3 — Topological sort (Kahn's algorithm)
// ---------------------------------------------------------------------------

/**
 * Kahn's algorithm. Modules ready at the same time are taken in manifest
 * declaration order, so `initOrder` is deterministic. The graph must be a DAG
 * (cycle detection has run).
 * @internal
 */
function topologicalSort(graph: DependencyGraph, validated: ValidatedManifests): readonly string[] {
	// Build declaration-order index for tie-breaking
	const declOrder = new Map<string, number>();
	for (let i = 0; i < validated.modules.length; i++) {
		declOrder.set(validated.modules[i].manifest.name, i);
	}

	// A node's in-degree counts the modules it depends on (its outgoing
	// edges); taking a node decrements its dependents via the reverse adjacency.
	const inDegree = new Map<string, number>();
	for (const node of graph.nodeOrder) {
		inDegree.set(node, graph.adj.get(node)?.size ?? 0);
	}

	// Ready queue: nodes whose in-degree is 0 (all prerequisites satisfied)
	const ready: string[] = [];
	for (const [node, deg] of inDegree) {
		if (deg === 0) ready.push(node);
	}

	const result: string[] = [];

	while (ready.length > 0) {
		// Sort ready queue by declaration order (stable tie-breaker)
		ready.sort((a, b) => (declOrder.get(a) ?? 0) - (declOrder.get(b) ?? 0));

		// biome-ignore lint/style/noNonNullAssertion: ready.length > 0 is the loop guard
		const node = ready.shift()!;
		result.push(node);

		// For each module that depends on `node`, decrement its in-degree
		for (const dependent of graph.radj.get(node) ?? []) {
			const newDeg = (inDegree.get(dependent) ?? 1) - 1;
			inDegree.set(dependent, newDeg);
			if (newDeg === 0) {
				ready.push(dependent);
			}
		}
	}

	return result;
}

// ---------------------------------------------------------------------------
// Step 4 — Per-component activation closure
// ---------------------------------------------------------------------------

/**
 * The `(moduleName, componentKey)` pairs to materialise, and, for those that
 * entered only through a seed (never through a require chain), which seed.
 * @internal
 */
interface ActivationClosure {
	/** All (module, key) pairs that should materialise. Key: `${module}::${key}`. */
	readonly inClosure: ReadonlySet<string>;
	/** Why each (module, key) pair that entered only as a seed was seeded: its first seed. */
	readonly seedOnly: ReadonlyMap<string, ActivationSeed>;
}

/**
 * Compound key for the closure sets. Assumes module names never contain
 * `"::"` (they are lowercase-hyphen identifiers by convention) and component
 * keys are strings (`ComponentMap` has no symbol keys). If either stops
 * holding, key the sets by module name (`Map<string, Set<ComponentKey>>`).
 * @internal
 */
function closureKey(module: string, componentKey: ComponentKey): string {
	return `${module}::${String(componentKey)}`;
}

/**
 * Slots core's own machinery reads after stage 3 (the CORS origins, the
 * issuer): a provider of one is always built, so core reads the slot, not the
 * configuration, whenever a module provides it.
 */
const CORE_READ_SLOTS: readonly ComponentKey[] = ["httpSettings", "oauthTokenSettings"];

/**
 * Computes the per-component activation closure. Its roots are the modules
 * with any `contributes` or `overrides` entry, and its seeds the components
 * with `lifecycle[K].eager === true`, and the providers of `CORE_READ_SLOTS`
 * and of `validated.federationStoreSlots` no host map fills; from each, the
 * module's `requires` and `optional` edges are walked recursively. A module is not all-or-nothing: each (module, key)
 * pair is decided on its own.
 * @internal
 */
function computeActivationClosure(
	validated: ValidatedManifests,
	virtualKeys: ReadonlySet<ComponentKey>,
): ActivationClosure {
	const inClosure = new Set<string>();
	/** Tracks all (module, key) pairs that entered via require-chain (not eager-seed). */
	const viaRequireChain = new Set<string>();
	/** Each (module, key) pair that entered via a seed, with its first seed. */
	const viaSeed = new Map<string, ActivationSeed>();

	/**
	 * Add a (module, key) pair to the closure, walking requires recursively.
	 * `source` indicates which path triggered this addition.
	 */
	function addToClosureAndWalk(
		vm: ValidatedModule,
		key: ComponentKey,
		source: "require-chain" | ActivationSeed,
	): void {
		const ck = closureKey(vm.manifest.name, key);
		if (source !== "require-chain") {
			if (!viaSeed.has(ck)) viaSeed.set(ck, source);
		} else {
			viaRequireChain.add(ck);
		}
		if (inClosure.has(ck)) return; // already in closure; no need to re-walk
		inClosure.add(ck);

		// Recursively walk this provider module's requires + optional edges
		walkModuleRequires(vm.normalised);
	}

	/**
	 * Walk a module's requires/optional and add the providing modules' keys to
	 * the closure (if not already present).
	 */
	function walkModuleRequires(norm: NormalisedModule): void {
		const allDeps = [...norm.requires, ...norm.optional];
		for (const key of allDeps) {
			if (virtualKeys.has(key)) continue;
			const provider = validated.providers.get(key);
			if (!provider) continue;
			addToClosureAndWalk(provider, key, "require-chain");
		}
	}

	// --- Closure roots: modules with contributes or overrides ---
	for (const vm of validated.modules) {
		const norm = vm.normalised;
		const isClosureRoot = norm.contributesEntries.length > 0 || norm.overridesEntries.length > 0;
		if (isClosureRoot) {
			// Walk this root's requires to bring in providers
			walkModuleRequires(norm);
		}
	}

	// --- Eager seeds: every (module, K) where lifecycle[K].eager === true ---
	for (const vm of validated.modules) {
		const lifecycle = vm.manifest.lifecycle ?? {};
		for (const [keyStr, entry] of Object.entries(lifecycle)) {
			const key = keyStr as ComponentKey;
			if (entry?.eager === true) {
				addToClosureAndWalk(vm, key, "eager");
			}
		}
	}

	// --- Core-read seeds: every provider of a slot core reads, unless a host fills it ---
	for (const key of CORE_READ_SLOTS) {
		if (virtualKeys.has(key)) continue;
		const provider = validated.providers.get(key);
		if (provider) addToClosureAndWalk(provider, key, "core-read");
	}

	// --- Federation-store seeds: every provider of a store an enabled federation needs, unless a host fills it ---
	for (const key of validated.federationStoreSlots) {
		if (virtualKeys.has(key)) continue;
		const provider = validated.providers.get(key);
		if (provider) addToClosureAndWalk(provider, key, "federation-store");
	}

	// --- Seed-only pairs: entered via a seed, never via a require chain ---
	const seedOnly = new Map<string, ActivationSeed>();
	for (const [ck, seed] of viaSeed) {
		if (!viaRequireChain.has(ck)) seedOnly.set(ck, seed);
	}
	return { inClosure, seedOnly };
}

// ---------------------------------------------------------------------------
// Step 5 — Build providerActivations and depsBlueprint
// ---------------------------------------------------------------------------

/**
 * Builds `providerActivations`, one entry per in-closure (module, key) pair
 * in init order, and `depsBlueprint`, covering every module with a
 * contributes or overrides entry or an in-closure provided key.
 * @internal
 */
function buildPlanOutputs(
	initOrder: readonly string[],
	validated: ValidatedManifests,
	closure: ActivationClosure,
): {
	providerActivations: readonly ProviderActivation[];
	depsBlueprint: ReadonlyMap<string, DepsBlueprint>;
} {
	const providerActivations: ProviderActivation[] = [];
	const depsBlueprint = new Map<string, DepsBlueprint>();

	for (const moduleName of initOrder) {
		const vm = validated.byName.get(moduleName);
		if (!vm) continue;
		const norm = vm.normalised;

		// Collect in-closure provides keys for this module
		const inClosureKeys: ComponentKey[] = [];
		for (const key of norm.providesKeys) {
			const ck = closureKey(moduleName, key);
			if (closure.inClosure.has(ck)) {
				inClosureKeys.push(key);
				const seededBy = closure.seedOnly.get(ck);
				const eager = seededBy === "eager" || seededBy === "core-read";
				providerActivations.push({
					module: moduleName,
					componentKey: key,
					eager,
					...(seededBy === undefined ? {} : { seededBy }),
				});
			}
		}

		// Module goes into depsBlueprint if it has contributes/overrides OR in-closure provides
		const hasContributions = norm.contributesEntries.length > 0 || norm.overridesEntries.length > 0;
		if (hasContributions || inClosureKeys.length > 0) {
			depsBlueprint.set(moduleName, {
				requires: norm.requires,
				optional: norm.optional,
			});
		}
	}

	return { providerActivations, depsBlueprint };
}

// ---------------------------------------------------------------------------
// Public API — planBoot
// ---------------------------------------------------------------------------

/**
 * Stage 2 of the boot planner. Pure: the same inputs give the same output or
 * the same error.
 *
 * 1. Dependency graph: modules are nodes, edges come from requires and
 *    optional keys; bootstrap and override keys are virtual providers.
 * 2. Cycle detection (Tarjan's SCC): a cycle or self-loop throws `BootError`
 *    `reason: "circular-dependency"`, `stage: "planBoot"`.
 * 3. Topological sort (Kahn's), ties broken by declaration order.
 * 4. Per-component activation closure from the contribute/override roots and
 *    the seeds (eager components, providers of slots core reads and of the
 *    stores an enabled federation needs); other siblings do not come along.
 * 5. `providerActivations` (per component, not per module) and
 *    `depsBlueprint` (lookup keys, not values).
 */
export function planBoot(
	validated: ValidatedManifests,
	bootstrapComponents: BootstrapMap,
	overrideComponents: Partial<ComponentMap> | undefined,
): BootPlan {
	// Collect virtual provider keys (bootstrap + override)
	const virtualKeys = new Set<ComponentKey>([
		...(Object.keys(bootstrapComponents) as ComponentKey[]),
		...(Object.keys(overrideComponents ?? {}) as ComponentKey[]),
	]);

	const graph = buildDependencyGraph(validated, virtualKeys);

	detectCycles(graph, validated);

	const initOrder = topologicalSort(graph, validated);

	const closure = computeActivationClosure(validated, virtualKeys);

	const { providerActivations, depsBlueprint } = buildPlanOutputs(initOrder, validated, closure);

	return {
		validated,
		initOrder,
		providerActivations,
		depsBlueprint,
	};
}
