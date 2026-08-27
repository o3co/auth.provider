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
import type { Express, RequestHandler, Router } from "express";
import type { InternalLifecycleRegistrar } from "../adapters/AdapterFactory.mjs";
import { planDiscoveryRoute } from "../discovery/planRoute.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { protectedResourceBindingMw } from "../middleware/protectedResourceBinding.mjs";
import {
	type DispatchPolicy,
	type TokenBindingMechanism,
	tokenBindingMw,
} from "../middleware/tokenBinding.mjs";
import type { ComponentKey } from "../modules/manifest/component-map.mjs";
import type { InternalReadinessRegistrar } from "../readiness/types.mjs";
import type {
	AppHandle,
	CleanupRecord,
	CollectedRouteContribution,
	FrozenWorld,
	ListCollector,
	OrderedRouteContribution,
} from "./types.mjs";
import { BootError } from "./types.mjs";

/**
 * The `express` package's runtime shape: a callable factory that produces an
 * `Express` app, with `Router` exposed as a property (CJS pattern). Captured
 * here so `assembleApp` can both construct a router AND wrap it inside an app
 * for `handle.listen()`.
 * @internal
 */
type ExpressFactory = (() => Express) & { Router: () => Router };

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
function buildDispose(
	frozen: FrozenWorld,
	lifecycleReg?: InternalLifecycleRegistrar,
): () => Promise<void> {
	let cachedPromise: Promise<void> | undefined;

	return function dispose(): Promise<void> {
		if (cachedPromise !== undefined) {
			return cachedPromise;
		}

		cachedPromise = (async () => {
			// Track errors alongside their (module, componentKey) origin so the
			// AggregateError message names which cleanup failed (per spec §6.3 /
			// §8.1: "errors are aggregated and surfaced through `dispose()`'s
			// rejection — see §6.3").
			const errorsWithOrigin: { module: string; componentKey: string; error: unknown }[] = [];

			// Step 1: iterate cleanups in reverse order (§8.1 steps 1-2).
			const reversedCleanups = [...frozen.cleanups].reverse() as CleanupRecord[];
			for (const record of reversedCleanups) {
				try {
					await record.cleanup(record.value);
				} catch (err) {
					errorsWithOrigin.push({
						module: record.module,
						componentKey: String(record.componentKey),
						error: err,
					});
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
							errorsWithOrigin.push({
								module: "(asyncDispose fallback)",
								componentKey: key,
								error: err,
							});
						}
					}
				}
			}

			// Step 3: D-5 LifecycleRegistrar drain (LIFO across all builder-
			// registered cleanups). Component cleanups (Steps 1-2) ran first
			// because they operate at the module level; sub-resource cleanups
			// (registered via LifecycleRegistrar) operate on resources owned by
			// those components. A Redis client backing a session store should
			// outlive the component's own cleanup so the component can issue a
			// final command if needed.
			if (lifecycleReg !== undefined) {
				const log = (frozen.components as Record<string, unknown>).logger as
					| { error(obj: unknown): void }
					| undefined;
				const fallbackLogger = { error: (obj: unknown) => console.error(obj) };
				const drainErrors = await lifecycleReg._drain(log ?? fallbackLogger);
				for (const err of drainErrors) {
					errorsWithOrigin.push({
						module: "(lifecycle-registrar)",
						componentKey: "(adapter-sub-resource)",
						error: err,
					});
				}
			}

			// Step 4: reject with AggregateError if any errors accumulated (§8.1 step 4).
			if (errorsWithOrigin.length > 0) {
				const originSummary = errorsWithOrigin
					.map((e) => `${e.module}:${e.componentKey}`)
					.join(", ");
				throw new AggregateError(
					errorsWithOrigin.map((e) => e.error),
					`AppHandle.dispose: ${errorsWithOrigin.length} cleanup error${
						errorsWithOrigin.length === 1 ? "" : "s"
					} (${originSummary})`,
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
	options: {
		readonly express?: { Router: () => Router };
		/**
		 * D-5: Boot-planner-owned LifecycleRegistrar threaded through createApp.
		 * `AppHandle.dispose()` drains the registrar's cleanups in LIFO order
		 * after the component-level cleanup steps (1-2) complete. Optional
		 * because direct callers of `assembleApp` (test harnesses) need not
		 * provide one — Steps 1-2 still run.
		 */
		readonly lifecycleReg?: InternalLifecycleRegistrar;
		/**
		 * Boot-planner-owned ReadinessRegistrar threaded through createApp. Its
		 * probes are exposed on `AppHandle.readinessProbes` for the composition
		 * root to mount behind a readiness route. Optional for the same reason
		 * `lifecycleReg` is: direct callers (test harnesses) need not supply one,
		 * and the handle then reports no probes.
		 */
		readonly readinessReg?: InternalReadinessRegistrar;
	} = {},
): AppHandle {
	// Resolve the Router constructor first — it is needed to build the
	// core-synthesized discovery route below, before the collision check. Accept
	// an injected value (for tests/overrides) or fall back to a synchronous
	// require of the express peer dep. The require also yields the express()
	// factory used by handle.listen() to wrap the router in a real Express app
	// (Router is middleware and would crash with "next is not a function" if
	// passed bare to createServer).
	let RouterCtor = options.express?.Router;
	let expressFactory: ExpressFactory | undefined;
	try {
		// createRequire is a built-in Node.js ESM helper (node:module).
		const req = createRequire(import.meta.url);
		const expressModule = req("express") as ExpressFactory;
		if (RouterCtor === undefined) RouterCtor = expressModule.Router;
		expressFactory = expressModule;
	} catch {
		// express not installed; expressFactory stays undefined and listen()
		// rejects at call time. RouterCtor is still usable when supplied via
		// options.express (test mocks).
	}

	if (RouterCtor === undefined) {
		throw new Error(
			"assembleApp: cannot resolve express. Install `express` as a peer dependency or provide options.express.Router.",
		);
	}

	// The OIDC discovery subsystem decides — from issuer config + provider-root
	// contributions — whether to synthesize a discovery route, and returns it as
	// an ORDINARY route contribution (mounted at "/", advertising
	// `GET /.well-known/openid-configuration`). All OIDC knowledge lives in
	// `discovery/`; from here discovery is just another route that flows through
	// the standard collision-check + mount-order + mount pipeline below, so a
	// module contributing a colliding route fails the boot fast with no special-
	// casing. `null` when no document is served.
	const discoveryRoute = planDiscoveryRoute({
		components: frozen.components as Record<string, unknown>,
		registries: frozen.registries,
		routerFactory: RouterCtor,
	});
	const allRoutes: readonly CollectedRouteContribution[] =
		discoveryRoute === null
			? frozen.routes
			: [
					...frozen.routes,
					{
						contribution: discoveryRoute,
						contributedBy: "core:discovery",
						declarationIndex: frozen.routes.length,
					},
				];

	// Pre-pass: post-apply route collision check (MUST-FIX 2 / §5.6 pre-pass).
	// Catches collisions produced by factory-generated routes that were opaque
	// at validate-manifests time, AND any module route colliding with the
	// synthesized discovery route. Same checks as stage 1, over the full list.
	checkMaterialisedRouteCollisions(allRoutes);

	// Step 1: Mount-order computation (§5.6 step 1).
	const ordered = computeMountOrder(allRoutes);

	// Step 2: Construct router (§5.6 step 2).
	const router: Router = RouterCtor();

	// The paths the protected-resource sender-constraint middleware (#264)
	// must NOT run on. Everything else is guarded — the mount below is GLOBAL,
	// not an allowlist of the surfaces that accept an access token. #308
	// shipped the allowlist shape (four literal paths coupled to the bundled
	// `oauthModule`'s mount points); #327 inverted it, because an allowlist
	// has to be kept in sync with every module's mount points, so a module
	// contributing a NEW token-accepting route shipped unguarded by default —
	// the silent-downgrade failure #308 fixed, reintroduced at the extension
	// seam. A global mount is safe because the middleware judges only requests
	// that actually present an access token: it passes through requests with
	// no Authorization header, non-token schemes (`Basic` client auth on the
	// introspection endpoint, browser-redirect flows), tokens that do not
	// decode as JWTs, and unbound tokens.
	//
	// `/oauth/token` is deliberately exempt: it authenticates a *client*, has
	// no access token in play, and runs the token-endpoint binding profile
	// above instead. The exempt path is coupled to the bundled `oauthModule`'s
	// mountPath the same way the `/oauth/token` mounts above and below are —
	// see the NOTE on the `grantMiddleware` mount.
	const SENDER_CONSTRAINT_EXEMPT_PATHS = ["/oauth/token"] as const;

	// Prefix-segment, case-insensitive match — the same semantics an Express
	// `router.use(path, ...)` mount applies (Express routers are
	// case-insensitive by default), so exempting a path exempts exactly the
	// sub-tree a literal mount on it would cover.
	const isSenderConstraintExempt = (path: string): boolean => {
		const lowered = path.toLowerCase();
		return SENDER_CONSTRAINT_EXEMPT_PATHS.some(
			(exempt) => lowered === exempt || lowered.startsWith(`${exempt}/`),
		);
	};

	// Synthesize a SINGLE `tokenBindingMw` from the `tokenBindingMechanisms`
	// collector and mount it on `/oauth/token` BEFORE any other grant
	// middleware. Multiple mechanism modules (DPoP, mTLS, ...) contribute
	// raw mechanisms; core composes them into one middleware so the
	// configured `DispatchPolicy` (`intent-explicit` / `strict-mutual-
	// exclusion`) arbitrates across modules. See ADR
	// `packages/core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md`
	// for the design rationale.
	//
	// Null entries (disabled-by-config) are filtered. When no mechanisms
	// are contributed, no middleware is synthesized.
	const mechanismCollector = frozen.registries.get("tokenBindingMechanisms") as
		| ListCollector<TokenBindingMechanism | null>
		| undefined;
	if (mechanismCollector !== undefined) {
		const mechanisms: TokenBindingMechanism[] = [];
		for (const m of mechanismCollector.values()) {
			if (m !== null) mechanisms.push(m);
		}
		if (mechanisms.length > 0) {
			const config = (frozen.components as Record<string, unknown>).config as
				| { oauth?: { tokenBinding?: { "dispatch-policy"?: unknown } } }
				| undefined;
			const rawPolicy = config?.oauth?.tokenBinding?.["dispatch-policy"];
			const dispatchPolicy: DispatchPolicy =
				rawPolicy === "strict-mutual-exclusion" ? "strict-mutual-exclusion" : "intent-explicit";
			const logger = (frozen.components as Record<string, unknown>).logger as Logger | undefined;
			const composed = tokenBindingMw({ mechanisms, dispatchPolicy, logger });
			router.use("/oauth/token", composed);
		}
	}

	// Mount the protected-resource sender-constraint middleware (#264). The
	// `/oauth/token` mount above establishes a binding so a grant can stamp it
	// into the issued token's `cnf`; this one holds the other end of that
	// promise, refusing a `cnf`-bearing token at the surfaces that accept an
	// access token as a credential unless the matching proof-of-possession
	// arrives with it. Without it a stolen DPoP- or mTLS-bound token replays
	// as a plain Bearer and the binding buys nothing.
	//
	// Mounted UNCONDITIONALLY — deliberately unlike the `/oauth/token` mount
	// above, which is skipped when no mechanisms are contributed. Access
	// tokens outlive a config change, so a deployment that removes its DPoP
	// module still has bound tokens in the wild; skipping the middleware there
	// would make those tokens silently downgrade to Bearer, which is the exact
	// failure this exists to prevent. With no mechanisms the middleware admits
	// every unbound token unchanged and refuses every bound one — fail closed.
	//
	// Mounted GLOBALLY, before every route contribution, so routes contributed
	// by modules core has never heard of are guarded the moment they mount —
	// see the exempt-list rationale above (#327).
	const protectedResourceMechanisms: TokenBindingMechanism[] = [];
	if (mechanismCollector !== undefined) {
		for (const m of mechanismCollector.values()) {
			if (m !== null) protectedResourceMechanisms.push(m);
		}
	}
	const protectedResourceMw = protectedResourceBindingMw({
		mechanisms: protectedResourceMechanisms,
		...(((frozen.components as Record<string, unknown>).logger as Logger | undefined)
			? { logger: (frozen.components as Record<string, unknown>).logger as Logger }
			: {}),
	});
	router.use((req, res, next) => {
		if (isSenderConstraintExempt(req.path)) {
			next();
			return;
		}
		// Returned so Express 5's router forwards a rejection to `next`.
		return protectedResourceMw(req, res, next);
	});

	// Mount `grantMiddleware` contributions on `/oauth/token` AFTER the
	// synthesized tokenBindingMw above. The bundled `oauthModule` contributes
	// its sub-router at mountPath `/oauth` (packages/oauth/src/module.mts),
	// so the external grant-dispatch URL is `/oauth/token`. Express runs
	// middleware in mount order, so these handlers fire before the OAuth
	// `/token` route handler the routes loop installs below. Null returns
	// (disabled-by-config path) are skipped here; the collector still
	// records them for value-identity dedup with other contributions.
	//
	// NOTE: this mount path is coupled to the bundled `oauthModule`'s
	// mountPath. A downstream that re-mounts the OAuth router at a different
	// path must also wrap or replace this composition step. Per Wave 2
	// Token-binding Cluster spec §4.7 / Phase 2 DPoP spec §11.1.
	const grantMwCollector = frozen.registries.get("grantMiddleware") as
		| ListCollector<RequestHandler | null>
		| undefined;
	if (grantMwCollector !== undefined) {
		for (const mw of grantMwCollector.values()) {
			if (mw !== null) {
				router.use("/oauth/token", mw);
			}
		}
	}

	// Mount each route contribution in mount-index order. The synthesized
	// discovery route (when present) is in `ordered` like any other, so it mounts
	// here through the same path — no special-casing.
	for (const orderedRoute of ordered) {
		router.use(orderedRoute.contribution.mountPath, orderedRoute.contribution.handler as never);
	}

	// Step 3: Construct AppHandle (§6.3).
	const dispose = buildDispose(frozen, options.lifecycleReg);

	const handle: AppHandle = {
		router,
		listen(port: number) {
			return new Promise((resolve, reject) => {
				if (expressFactory === undefined) {
					reject(
						new Error(
							"assembleApp.listen: express factory unavailable; install `express` as a peer dependency.",
						),
					);
					return;
				}
				// Wrap the router in a real Express app so unmatched requests get
				// the standard Express finalhandler (404) instead of crashing on
				// "next is not a function". An Express Router is middleware that
				// expects an outer (req, res, next) caller; createServer would
				// invoke it with (req, res) only.
				const app = expressFactory();
				app.use(router);
				const server = createServer(app);
				server.listen(port, () => {
					resolve(server);
				});
				server.once("error", reject);
			});
		},
		dispose,
		components: frozen.components,
		routes: ordered,
		readinessProbes: options.readinessReg?._probes() ?? [],
	};

	// Theme D: freeze the whole AppHandle before returning (§6.3).
	return Object.freeze(handle);
}
