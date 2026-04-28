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
 * boot/plan-boot.mts — Stage 2 of the A2-β boot planner pipeline.
 *
 * Accepts `ValidatedManifests` (output of stage 1), `bootstrapComponents`,
 * and `overrideComponents`; runs five ordered steps:
 *  1. Build dependency graph
 *  2. Cycle detection (Tarjan's SCC)
 *  3. Topological sort (Kahn's algorithm, declaration-order tie-breaker)
 *  4. Per-component activation closure (contribute/override roots + eager seeds)
 *  5. Build `providerActivations` and `depsBlueprint`
 *
 * Returns a `BootPlan` on success. Throws `BootError` with
 * `reason: "circular-dependency"` on the first detected cycle.
 *
 * The stage is **pure**: same inputs → same output / same error.
 *
 * Per A2-β §5.2.
 */

import type { ComponentKey, ComponentMap } from "../modules/manifest/component-map.mjs";
import type {
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
// Per A2-β §5.2 step 1.
// ---------------------------------------------------------------------------

/**
 * An adjacency-list dependency graph. Edges represent "A depends on B"
 * (A `requires` a component key that B `provides`).
 * Bootstrap and override keys are pre-seeded as virtual providers —
 * requirements satisfied by them produce no edges.
 *
 * Per A2-β §5.2 step 1.
 * @internal
 */
interface DependencyGraph {
	/** All module names (nodes), in input declaration order. */
	readonly nodeOrder: readonly string[];
	/**
	 * Adjacency list: for each module name, the set of module names it
	 * depends on (i.e. whose provides must run before this module's requires
	 * are satisfied). Edges from requires + optional (optional only when
	 * satisfiable by another module, not by bootstrap/override).
	 */
	readonly adj: ReadonlyMap<string, ReadonlySet<string>>;
	/** Reverse adjacency: for each module, who depends on it. */
	readonly radj: ReadonlyMap<string, ReadonlySet<string>>;
}

/**
 * Build the dependency graph from `ValidatedManifests` plus the set of keys
 * that are pre-seeded as virtual providers (bootstrap + override keys).
 *
 * Per A2-β §5.2 step 1.
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
	 * Add a directed edge from `from` (the requiring module) to `to` (the
	 * providing module). Self-edges (from === to) are intentionally allowed so
	 * that Tarjan's SCC + the cycle-detection escalation check can detect
	 * self-cycles and throw `BootError reason="circular-dependency"`.
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
// Per A2-β §5.2 step 2.
// ---------------------------------------------------------------------------

/**
 * Tarjan's strongly-connected-components algorithm.
 * Returns an array of SCCs; each SCC is an array of module names.
 * Non-trivial SCCs (size > 1) and self-loops are the cycles.
 *
 * Per A2-β §5.2 step 2.
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
 * Given a non-trivial SCC (a cycle), reconstruct the spec-shaped cycle chain:
 * `{ module, requires, satisfiedBy }[]` — "A requires key X (provided by B)".
 *
 * Per A2-β §6.1 CircularDependencyDetails.cycle normative shape.
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

	// Pick starting node — smallest declaration index in the SCC
	let start = scc[0];
	for (const name of scc) {
		if ((indexByName.get(name) ?? 0) < (indexByName.get(start) ?? 0)) {
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
 * Detect cycles in the dependency graph and throw `BootError` with
 * `reason: "circular-dependency"` if a non-trivial SCC or self-loop is found.
 *
 * Per A2-β §5.2 step 2.
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
// Per A2-β §5.2 step 3.
// ---------------------------------------------------------------------------

/**
 * Kahn's algorithm topological sort with declaration-order tie-breaking.
 *
 * When multiple modules are simultaneously ready (in-degree = 0), they are
 * sorted by their manifest declaration order (input array index). This makes
 * `initOrder` deterministic across identical input lists.
 *
 * Precondition: the graph is a DAG (cycle detection has already run).
 *
 * Per A2-β §5.2 step 3.
 * @internal
 */
function topologicalSort(graph: DependencyGraph, validated: ValidatedManifests): readonly string[] {
	// Build declaration-order index for tie-breaking
	const declOrder = new Map<string, number>();
	for (let i = 0; i < validated.modules.length; i++) {
		declOrder.set(validated.modules[i].manifest.name, i);
	}

	// inDegree[node] = number of other modules this node depends on
	// (i.e. the count of outgoing requires/optional edges from this node).
	// Kahn's algorithm pops nodes whose inDegree drops to 0, then walks the
	// reverse adjacency to decrement dependents.
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
// Per A2-β §5.2 step 4.
// ---------------------------------------------------------------------------

/**
 * Activation closure result: a set of `(moduleName, componentKey)` pairs to
 * materialise, plus a set that entered ONLY via eager-seed (not via require
 * chain). The intersection of the two sets gives "entered via both paths".
 *
 * Per A2-β §5.2 step 4.
 * @internal
 */
interface ActivationClosure {
	/** All (module, key) pairs that should materialise. Key: `${module}::${key}`. */
	readonly inClosure: ReadonlySet<string>;
	/** (module, key) pairs that entered the closure exclusively via eager-seed. */
	readonly eagerOnlyKeys: ReadonlySet<string>;
}

/**
 * Compound key for activation closure sets.
 * @internal
 */
function closureKey(module: string, componentKey: ComponentKey): string {
	return `${module}::${String(componentKey)}`;
}

/**
 * Compute the per-component activation closure.
 *
 * Closure roots:
 * - Modules with any non-empty `contributes` or `overrides` entries (Theme E).
 *
 * Eager seeds:
 * - Every component K where `lifecycle[K].eager === true` in any module.
 *
 * Expansion:
 * - If (module, K) is in the closure, walk that module's `requires` (and
 *   optional) edges recursively.
 *
 * Non-eager sibling rule: a module is NOT all-or-nothing — each (module, key)
 * pair is evaluated independently.
 *
 * Per A2-β §5.2 step 4.
 * @internal
 */
function computeActivationClosure(
	validated: ValidatedManifests,
	virtualKeys: ReadonlySet<ComponentKey>,
): ActivationClosure {
	const inClosure = new Set<string>();
	/** Tracks all (module, key) pairs that entered via require-chain (not eager-seed). */
	const viaRequireChain = new Set<string>();
	/** Tracks all (module, key) pairs that entered via eager-seed. */
	const viaEagerSeed = new Set<string>();

	/**
	 * Add a (module, key) pair to the closure, walking requires recursively.
	 * `source` indicates which path triggered this addition.
	 */
	function addToClosureAndWalk(
		vm: ValidatedModule,
		key: ComponentKey,
		source: "require-chain" | "eager",
	): void {
		const ck = closureKey(vm.manifest.name, key);
		if (source === "eager") {
			viaEagerSeed.add(ck);
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

	// --- Compute eagerOnlyKeys: in viaEagerSeed but NOT in viaRequireChain ---
	const eagerOnlyKeys = new Set<string>();
	for (const ck of viaEagerSeed) {
		if (!viaRequireChain.has(ck)) {
			eagerOnlyKeys.add(ck);
		}
	}

	return { inClosure, eagerOnlyKeys };
}

// ---------------------------------------------------------------------------
// Steps 5 + 6 — Build providerActivations and depsBlueprint
// Per A2-β §5.2 steps 5 + 6.
// ---------------------------------------------------------------------------

/**
 * Build the `providerActivations` list and `depsBlueprint` map.
 *
 * `providerActivations` is in topological + declaration-order (initOrder) with
 * one entry per (module, key) pair that is in the activation closure.
 *
 * `depsBlueprint` covers every module that:
 * - has any contributes/overrides entries, OR
 * - has any in-closure provides keys.
 *
 * Per A2-β §5.2 steps 5 + 6.
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
				const eager = closure.eagerOnlyKeys.has(ck);
				providerActivations.push({ module: moduleName, componentKey: key, eager });
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
 * Stage 2 of the A2-β boot planner pipeline.
 *
 * Takes `ValidatedManifests` (from stage 1), `bootstrapComponents`, and
 * `overrideComponents`; runs the dependency graph, cycle detection, topological
 * sort, per-component activation closure, and emits a `BootPlan`.
 *
 * The function is **pure**: same inputs → same output / same error.
 *
 * Steps:
 * 1. Build dependency graph — nodes = modules, edges from requires + optional
 *    (advisory). Bootstrap/override keys are pre-seeded virtual providers.
 * 2. Cycle detection — Tarjan's SCC; non-trivial SCCs or self-loops throw
 *    `BootError` with `reason: "circular-dependency"`, `stage: "planBoot"`.
 * 3. Topological sort — Kahn's algorithm with declaration-order tie-breaker.
 * 4. Per-component activation closure — closure roots = modules with any
 *    contributes/overrides; eager seeds = `lifecycle[K].eager === true`; both
 *    walk the requires graph recursively. Non-eager siblings do NOT piggy-back.
 * 5. Build `providerActivations` (per-component, not per-module) and
 *    `depsBlueprint` (lookup keys, not values).
 *
 * Per A2-β §5.2.
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

	// Step 1: Build dependency graph. Per A2-β §5.2 step 1.
	const graph = buildDependencyGraph(validated, virtualKeys);

	// Step 2: Cycle detection. Per A2-β §5.2 step 2.
	detectCycles(graph, validated);

	// Step 3: Topological sort (Kahn's + declaration-order tie-breaker). Per A2-β §5.2 step 3.
	const initOrder = topologicalSort(graph, validated);

	// Step 4: Per-component activation closure. Per A2-β §5.2 step 4.
	const closure = computeActivationClosure(validated, virtualKeys);

	// Steps 5 + 6: Build providerActivations and depsBlueprint. Per A2-β §5.2 steps 5 + 6.
	const { providerActivations, depsBlueprint } = buildPlanOutputs(initOrder, validated, closure);

	return {
		validated,
		initOrder,
		providerActivations,
		depsBlueprint,
	};
}
