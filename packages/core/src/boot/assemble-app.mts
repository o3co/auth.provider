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
 * boot/assemble-app.mts — Stage 6 of the A2-β boot planner pipeline.
 *
 * Takes the `FrozenWorld` from stage 5, computes mount order via Kahn's
 * topological sort over `before`/`after` route tokens with
 * `declarationIndex` as tie-breaker, constructs an Express Router with all
 * routes mounted in mount-index order, and builds the public `AppHandle`.
 *
 * Per A2-β §5.6 + §6.3 + §8.1.
 */

import { createServer } from "node:http";
import { createRequire } from "node:module";
import type { Router } from "express";
import type { ComponentKey } from "../modules/manifest/component-map.mjs";
import type {
	AppHandle,
	CleanupRecord,
	CollectedRouteContribution,
	FrozenWorld,
	OrderedRouteContribution,
} from "./types.mjs";
import { BootError } from "./types.mjs";

// ---------------------------------------------------------------------------
// Internal: post-apply route collision check (§5.6 pre-pass, MUST-FIX 2)
// ---------------------------------------------------------------------------

/**
 * Run the same route-collision checks that validate-manifests performs for
 * static contributions, but against the FULL materialised route list (which
 * includes factory-produced routes that were opaque at stage 1).
 *
 * This is defence-in-depth: validate-manifests catches static violations
 * early; this pass catches factory-produced violations at stage 6.
 *
 * Checks:
 *  - Duplicate id (`duplicate-contribute` identityKind="id")
 *  - Duplicate mountPath with no id (`duplicate-contribute` identityKind="mountPath")
 *  - Effective (method, mountPath+adv.path) collision (`duplicate-contribute` identityKind="effective-method-path")
 *  - RouteAdvertisement.path missing leading slash (`invalid-route-advertisement-path`)
 *
 * Per A2-β §5.1 step 7 (factory-produced extension), §5.6 pre-pass.
 * @internal
 */
function checkMaterialisedRouteCollisions(routes: readonly CollectedRouteContribution[]): void {
	// 7a: Duplicate id check
	const seenIds = new Map<string, string>(); // id → module
	for (const { contribution: route, contributedBy: module } of routes) {
		if (route.id !== undefined) {
			const prev = seenIds.get(route.id);
			if (prev !== undefined) {
				throw new BootError({
					message: `assembleApp: duplicate route id "${route.id}" — modules "${prev}" and "${module}" both declare it.`,
					reason: "duplicate-contribute",
					stage: "assembleApp",
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
	for (const { contribution: route, contributedBy: module } of routes) {
		if (route.id === undefined) {
			const prev = seenMountPaths.get(route.mountPath);
			if (prev !== undefined) {
				throw new BootError({
					message: `assembleApp: duplicate mountPath "${route.mountPath}" (no id) — modules "${prev}" and "${module}" both declare it.`,
					reason: "duplicate-contribute",
					stage: "assembleApp",
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
	const seenEffective = new Map<string, { module: string; mountPath: string }>();

	for (const { contribution: route, contributedBy: module } of routes) {
		if (!route.routes) continue;
		for (const adv of route.routes) {
			// 7d: leading-slash check
			if (!adv.path.startsWith("/")) {
				throw new BootError({
					message: `assembleApp: RouteAdvertisement.path "${adv.path}" in module "${module}" (mountPath "${route.mountPath}") must start with "/".`,
					reason: "invalid-route-advertisement-path",
					stage: "assembleApp",
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
					message: `assembleApp: effective route collision "${effectiveIdentity}" — modules "${prev.module}" and "${module}" both declare it.`,
					reason: "duplicate-contribute",
					stage: "assembleApp",
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
// Internal: mount-order computation (§5.6 step 1)
// ---------------------------------------------------------------------------

/**
 * Resolve mount order for a list of collected route contributions using
 * Kahn's topological sort. Declaration order (declarationIndex) is the
 * tie-breaker when multiple nodes are simultaneously ready.
 *
 * Throws `BootError reason="route-order-cycle"` if a cycle is detected.
 * Throws `BootError reason="route-order-target-missing"` if a referenced id
 * does not exist (defence-in-depth).
 */
function computeMountOrder(
	routes: readonly CollectedRouteContribution[],
): readonly OrderedRouteContribution[] {
	if (routes.length === 0) {
		return [];
	}

	// Build id → index map for fast lookup.
	const idToIndex = new Map<string, number>();
	for (let i = 0; i < routes.length; i++) {
		const r = routes[i];
		if (r !== undefined && r.contribution.id !== undefined) {
			idToIndex.set(r.contribution.id, i);
		}
	}

	// inDegree[i] = number of incoming edges for node i (must wait for others)
	const inDegree = new Array<number>(routes.length).fill(0);
	// adjacency[i] = set of nodes that must come AFTER node i
	const adjacency: Set<number>[] = Array.from({ length: routes.length }, () => new Set<number>());

	for (let i = 0; i < routes.length; i++) {
		const r = routes[i];
		if (r === undefined) continue;
		const { before, after, id } = r.contribution;

		// before: [targetId, ...] → edge i → target (i mounts before target)
		if (before !== undefined) {
			for (const targetId of before) {
				const targetIdx = idToIndex.get(targetId);
				if (targetIdx === undefined) {
					throw new BootError({
						message: `assembleApp: route-order-target-missing — route '${id ?? r.contribution.mountPath}' references unknown before-target '${targetId}'`,
						reason: "route-order-target-missing",
						stage: "assembleApp",
						details: {
							reason: "route-order-target-missing",
							id: targetId,
							referencedBy: id ?? null,
							...(id === undefined ? { referencedByMountPath: r.contribution.mountPath } : {}),
							direction: "before",
						},
					});
				}
				const adjI = adjacency[i];
				const currentDeg = inDegree[targetIdx];
				if (adjI !== undefined && currentDeg !== undefined && !adjI.has(targetIdx)) {
					adjI.add(targetIdx);
					inDegree[targetIdx] = currentDeg + 1;
				}
			}
		}

		// after: [targetId, ...] → edge target → i (i mounts after target)
		if (after !== undefined) {
			for (const targetId of after) {
				const targetIdx = idToIndex.get(targetId);
				if (targetIdx === undefined) {
					throw new BootError({
						message: `assembleApp: route-order-target-missing — route '${id ?? r.contribution.mountPath}' references unknown after-target '${targetId}'`,
						reason: "route-order-target-missing",
						stage: "assembleApp",
						details: {
							reason: "route-order-target-missing",
							id: targetId,
							referencedBy: id ?? null,
							...(id === undefined ? { referencedByMountPath: r.contribution.mountPath } : {}),
							direction: "after",
						},
					});
				}
				const adjTarget = adjacency[targetIdx];
				const currentDegI = inDegree[i];
				if (adjTarget !== undefined && currentDegI !== undefined && !adjTarget.has(i)) {
					adjTarget.add(i);
					inDegree[i] = currentDegI + 1;
				}
			}
		}
	}

	// Kahn's algorithm with declarationIndex tie-breaker.
	// Maintain a sorted-by-declarationIndex ready queue.
	const ready: number[] = [];
	for (let i = 0; i < routes.length; i++) {
		if (inDegree[i] === 0) {
			ready.push(i);
		}
	}
	// Sort ascending by declarationIndex.
	ready.sort((a, b) => (routes[a]?.declarationIndex ?? 0) - (routes[b]?.declarationIndex ?? 0));

	const ordered: OrderedRouteContribution[] = [];
	while (ready.length > 0) {
		// Take the front element (lowest declarationIndex among ready nodes).
		const idx = ready.shift();
		if (idx === undefined) break;
		const r = routes[idx];
		if (r === undefined) continue;
		ordered.push({
			contribution: r.contribution,
			contributedBy: r.contributedBy,
			mountIndex: ordered.length,
		});

		// Reduce in-degree for all successors; collect newly-ready ones.
		const newlyReady: number[] = [];
		const adjSet = adjacency[idx];
		if (adjSet !== undefined) {
			for (const successor of adjSet) {
				const prev = inDegree[successor];
				if (prev !== undefined) {
					const next = prev - 1;
					inDegree[successor] = next;
					if (next === 0) {
						newlyReady.push(successor);
					}
				}
			}
		}

		if (newlyReady.length > 0) {
			// Sort newly-ready by declarationIndex and merge into ready queue.
			newlyReady.sort(
				(a, b) => (routes[a]?.declarationIndex ?? 0) - (routes[b]?.declarationIndex ?? 0),
			);
			for (const nr of newlyReady) {
				// Insert in sorted position (ascending declarationIndex).
				const nrDecl = routes[nr]?.declarationIndex ?? 0;
				let insertAt = ready.length;
				for (let k = 0; k < ready.length; k++) {
					const readyK = ready[k];
					if (readyK !== undefined && (routes[readyK]?.declarationIndex ?? 0) > nrDecl) {
						insertAt = k;
						break;
					}
				}
				ready.splice(insertAt, 0, nr);
			}
		}
	}

	// If we didn't consume all nodes, a cycle exists.
	if (ordered.length !== routes.length) {
		// Identify cycle nodes: those still with inDegree > 0.
		const cycleNodes = routes
			.map((r, i) => ({ r, i }))
			.filter(({ i }) => (inDegree[i] ?? 0) > 0)
			.map(({ r }) => ({
				id: r.contribution.id ?? r.contribution.mountPath,
				...(r.contribution.before !== undefined ? { before: r.contribution.before } : {}),
				...(r.contribution.after !== undefined ? { after: r.contribution.after } : {}),
			}));

		throw new BootError({
			message: `assembleApp: route-order-cycle detected among ${cycleNodes.length} route(s)`,
			reason: "route-order-cycle",
			stage: "assembleApp",
			details: {
				reason: "route-order-cycle",
				cycle: cycleNodes as ReadonlyArray<{
					readonly id: string;
					readonly before?: readonly string[];
					readonly after?: readonly string[];
				}>,
			},
		});
	}

	return ordered;
}

// ---------------------------------------------------------------------------
// Internal: dispose builder (§8.1)
// ---------------------------------------------------------------------------

/**
 * Build the single-shot dispose function for AppHandle.
 * Iterates cleanups in reverse order, then falls back to Symbol.asyncDispose
 * for components without an explicit cleanup. Errors accumulate into
 * AggregateError.
 *
 * Per A2-β §8.1.
 */
function buildDispose(frozen: FrozenWorld): () => Promise<void> {
	let cachedPromise: Promise<void> | undefined;

	return function dispose(): Promise<void> {
		if (cachedPromise !== undefined) {
			return cachedPromise;
		}

		cachedPromise = (async () => {
			const errors: unknown[] = [];

			// Step 1: iterate cleanups in reverse order (§8.1 steps 1-2).
			const reversedCleanups = [...frozen.cleanups].reverse() as CleanupRecord[];
			for (const record of reversedCleanups) {
				try {
					await record.cleanup(record.value);
				} catch (err) {
					errors.push(err);
				}
			}

			// Step 2: Symbol.asyncDispose fallback (§8.1 step 3).
			// Only for components without an explicit lifecycle[K].cleanup AND
			// that were NOT provided by the host environment (bootstrap or
			// override). External values are consumer-owned: their lifecycle is
			// outside the boot planner's responsibility. Per A2-β §5.3 / §8.1.
			const explicitCleanupKeys = new Set<ComponentKey>(frozen.cleanups.map((r) => r.componentKey));

			for (const [key, value] of Object.entries(frozen.components)) {
				if (explicitCleanupKeys.has(key as ComponentKey)) {
					// Explicit cleanup was declared for this key; skip Symbol.asyncDispose.
					continue;
				}
				if (frozen.externalKeys.has(key as ComponentKey)) {
					// Consumer-owned key (bootstrap or override); skip Symbol.asyncDispose.
					continue;
				}
				if (value !== null && value !== undefined) {
					const asyncDispose = (value as Record<symbol, unknown>)[Symbol.asyncDispose];
					if (typeof asyncDispose === "function") {
						try {
							await (asyncDispose as () => Promise<void>).call(value);
						} catch (err) {
							errors.push(err);
						}
					}
				}
			}

			// Step 4: reject with AggregateError if any errors accumulated (§8.1 step 4).
			if (errors.length > 0) {
				throw new AggregateError(
					errors,
					`AppHandle.dispose: ${errors.length} cleanup error${errors.length === 1 ? "" : "s"}`,
				);
			}
		})();

		return cachedPromise;
	};
}

// ---------------------------------------------------------------------------
// Public: assembleApp (stage 6)
// ---------------------------------------------------------------------------

/**
 * Stage 6 of the A2-β boot planner pipeline.
 *
 * Takes the `FrozenWorld` from stage 5, computes mount order (Kahn's
 * topological sort over `before`/`after` route tokens with cycle detection),
 * constructs an Express Router with all routes mounted in mount-index order,
 * and builds the public `AppHandle` with `router`, `listen(port)`,
 * `dispose()`, and `components`.
 *
 * The construction phase is synchronous. `listen` and `dispose` on the
 * returned handle are async.
 *
 * Per A2-β §5.6 + §6.3 + §8.1.
 */
export function assembleApp(
	frozen: FrozenWorld,
	options: { readonly express?: { Router: () => Router } } = {},
): AppHandle {
	// Pre-pass: post-apply route collision check (MUST-FIX 2 / §5.6 pre-pass).
	// Catches collisions produced by factory-generated routes that were opaque
	// at validate-manifests time. Same checks as stage 1, but runs against the
	// full materialised frozen.routes list.
	checkMaterialisedRouteCollisions(frozen.routes);

	// Step 1: Mount-order computation (§5.6 step 1).
	const ordered = computeMountOrder(frozen.routes);

	// Step 2: Construct router (§5.6 step 2).
	// Resolve Router constructor: accept injected value (for tests/overrides)
	// or fall back to a synchronous require of the express peer dep.
	let RouterCtor = options.express?.Router;
	if (RouterCtor === undefined) {
		// express is declared as an optional peer dep; use sync require fallback.
		// createRequire is a built-in Node.js ESM helper (node:module).
		const req = createRequire(import.meta.url);
		const expressModule = req("express") as { Router: () => Router };
		RouterCtor = expressModule.Router;
	}

	const router: Router = RouterCtor();

	// Mount each route contribution in mount-index order.
	for (const orderedRoute of ordered) {
		router.use(orderedRoute.contribution.mountPath, orderedRoute.contribution.handler as never);
	}

	// Step 3: Construct AppHandle (§6.3).
	const dispose = buildDispose(frozen);

	const handle: AppHandle = {
		router,
		listen(port: number) {
			return new Promise((resolve, reject) => {
				const server = createServer(router as never);
				server.listen(port, () => {
					resolve(server);
				});
				server.once("error", reject);
			});
		},
		dispose,
		components: frozen.components,
	};

	// Theme D: freeze the whole AppHandle before returning (§6.3).
	return Object.freeze(handle);
}
