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
 * boot/assemble-app.mts: stage 6 of the boot planner. Takes the `FrozenWorld`
 * from stage 5, orders routes by Kahn's topological sort over `before`/`after`
 * tokens (`declarationIndex` breaks ties), mounts them on an Express Router
 * with core's terminal error handler after them
 * (`middleware/terminalError.mts`), and builds the public `AppHandle`.
 */

import { createServer } from "node:http";
import { createRequire } from "node:module";
import type { Express, Request, RequestHandler, Router } from "express";
import type { InternalLifecycleRegistrar } from "../adapters/AdapterFactory.mjs";
import { discoveryRouteFor, planDiscoveryDocument } from "../discovery/planRoute.mjs";
import type { OidcDiscoveryContribution } from "../discovery/types.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { browserFacingCorsRoutes, corsMw } from "../middleware/cors.mjs";
import { protectedResourceBindingMw } from "../middleware/protectedResourceBinding.mjs";
import { terminalErrorHandler } from "../middleware/terminalError.mjs";
import {
	type DispatchPolicy,
	resolveTokenBindingSettings,
	type TokenBindingMechanism,
	tokenBindingMw,
} from "../middleware/tokenBinding.mjs";
import type { ComponentKey } from "../modules/manifest/component-map.mjs";
import { normalizeAllowedOrigins } from "../net/origin.mjs";
import type { InternalReadinessRegistrar } from "../readiness/types.mjs";
import { failureDetail } from "./failure-summary.mjs";
import { compositionIssuer } from "./oauth-token-settings.mjs";
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

/** The issuer the CORS table's discovery paths derive from: the composition's, when it is a string. */
const corsIssuerOptions = (
	components: Readonly<Record<string, unknown>>,
): { readonly issuer?: string } => {
	const issuer = compositionIssuer(components);
	return typeof issuer === "string" ? { issuer } : {};
};

// ---------------------------------------------------------------------------
// Internal: post-apply route collision check
// ---------------------------------------------------------------------------

/**
 * Run the route-collision checks validate-manifests performs for static
 * contributions again, over the FULL materialised route list, which includes
 * factory-produced routes that were opaque at stage 1:
 *  - Duplicate id (`duplicate-contribute` identityKind="id")
 *  - Duplicate mountPath with no id (`duplicate-contribute` identityKind="mountPath")
 *  - Effective (method, mountPath+adv.path) collision (`duplicate-contribute` identityKind="effective-method-path")
 *  - RouteAdvertisement.path missing leading slash (`invalid-route-advertisement-path`)
 * @internal
 */
function checkMaterialisedRouteCollisions(routes: readonly CollectedRouteContribution[]): void {
	// Duplicate id check
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

	// Duplicate mountPath (no id) check
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

	// RouteAdvertisement checks
	const seenEffective = new Map<string, { module: string; mountPath: string }>();

	for (const { contribution: route, contributedBy: module } of routes) {
		if (!route.routes) continue;
		for (const adv of route.routes) {
			// Leading-slash check
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

			// Effective method+path collision
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
// Internal: mount-order computation
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
						message: `assembleApp: route-order-target-missing — route '${id ?? r.contribution.mountPath}' of module "${r.contributedBy}" references unknown before-target '${targetId}'`,
						reason: "route-order-target-missing",
						stage: "assembleApp",
						details: {
							reason: "route-order-target-missing",
							id: targetId,
							referencedBy: id ?? null,
							...(id === undefined ? { referencedByMountPath: r.contribution.mountPath } : {}),
							referencedByModule: r.contributedBy,
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
						message: `assembleApp: route-order-target-missing — route '${id ?? r.contribution.mountPath}' of module "${r.contributedBy}" references unknown after-target '${targetId}'`,
						reason: "route-order-target-missing",
						stage: "assembleApp",
						details: {
							reason: "route-order-target-missing",
							id: targetId,
							referencedBy: id ?? null,
							...(id === undefined ? { referencedByMountPath: r.contribution.mountPath } : {}),
							referencedByModule: r.contributedBy,
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
// Internal: dispose builder
// ---------------------------------------------------------------------------

/**
 * Build the single-shot dispose function for AppHandle: explicit cleanups in
 * reverse order, then Symbol.asyncDispose for components without one, then
 * the LifecycleRegistrar drain. Errors accumulate into an AggregateError.
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
			// AggregateError message names which cleanup failed.
			const errorsWithOrigin: { module: string; componentKey: string; error: unknown }[] = [];

			// Step 1: iterate cleanups in reverse order.
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

			// Step 2: Symbol.asyncDispose fallback, only for components without an
			// explicit lifecycle[K].cleanup that the host did NOT provide
			// (bootstrap or override): external values are consumer-owned.
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

			// Step 3: LifecycleRegistrar drain (LIFO across builder-registered
			// cleanups), after the component cleanups: a sub-resource such as the
			// Redis client behind a session store must outlive the component's own
			// cleanup so the component can issue a final command.
			if (lifecycleReg !== undefined) {
				// The logger component when one is wired, else `consoleLogger`:
				// either way one object-first line per failed cleanup.
				const log = (frozen.components as Record<string, unknown>).logger as Logger | undefined;
				const drainErrors = await lifecycleReg._drain(log ?? consoleLogger, "dispose");
				for (const err of drainErrors) {
					errorsWithOrigin.push({
						module: "(lifecycle-registrar)",
						componentKey: "(adapter-sub-resource)",
						error: err,
					});
				}
			}

			// Step 4: reject with AggregateError if any errors accumulated.
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
 * Stage 6 of the boot planner.
 *
 * Takes the `FrozenWorld` from stage 5, computes mount order (Kahn's
 * topological sort over `before`/`after` route tokens with cycle detection),
 * constructs an Express Router with all routes mounted in mount-index order,
 * and builds the public `AppHandle` with `router`, `listen(port)`,
 * `dispose()`, and `components`. Construction is synchronous; `listen` and
 * `dispose` on the returned handle are async.
 */
export function assembleApp(
	frozen: FrozenWorld,
	options: {
		readonly express?: { Router: () => Router };
		/**
		 * Boot-planner-owned LifecycleRegistrar threaded through createApp.
		 * `AppHandle.dispose()` drains it in LIFO order after the component
		 * cleanups. Optional: direct callers (test harnesses) need not provide
		 * one.
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

	// The OIDC discovery subsystem decides, from issuer config and provider-root
	// contributions, whether to synthesize a discovery route, and returns it as
	// an ORDINARY route contribution (mounted at "/", advertising
	// `GET /.well-known/openid-configuration`). All OIDC knowledge lives in
	// `discovery/`; from here the route flows through the standard
	// collision-check, mount-order and mount pipeline below, so a colliding
	// module route fails the boot. `null` when no document is served.
	//
	// The collector is cast here, not in `discovery/`: mapping a contribution
	// kind to its collector is what assembly knows. The other inputs arrive
	// typed from the frozen components.
	const collector = frozen.registries.get("discoveryMetadata") as
		| ListCollector<OidcDiscoveryContribution>
		| undefined;
	// No `try` here. The planner hands back a document that failed to validate
	// as a value, and only that. The host-supplied code it reads (the key
	// store's algorithm, this collector, a contribution's `providerRoot`) and
	// the router factory `discoveryRouteFor` calls below are outside any
	// conversion: whatever they throw arrives as itself.
	const planning = planDiscoveryDocument({
		// The oauth module's `oauthTokenSettings` when the composition holds it,
		// otherwise the configuration's issuer. The planner validates what it
		// is handed.
		issuer: compositionIssuer(frozen.components as Record<string, unknown>) as string | undefined,
		// `KeyStore.algorithm` is typed, but a host may put an object of its own
		// in the slot through `bootstrapComponents` / `overrideComponents`,
		// unchecked at that boundary, so the read is guarded. A reader, so the
		// step reads it only once both activation conditions have passed.
		readSigningAlgs: () => {
			const algorithm = frozen.components.keyStore?.algorithm;
			return typeof algorithm === "string" ? [algorithm] : [];
		},
		// A reader, like the one above, so the collector is iterated only once
		// an issuer has been found — not while this argument is being built.
		readMetadata: () => (collector === undefined ? [] : [...collector.values()]),
	});
	if (planning.outcome === "invalid") {
		// Converted here, not in the step: a discovery misconfiguration surfaces
		// as a `BootError` like every other assembleApp failure. The planner's
		// text goes by its projection (`failureDetail`), in the message and in
		// `details.detail` alike, never the message itself: see
		// `failure-summary.mts`.
		const detail = failureDetail(planning.error);
		throw new BootError({
			message: `assembleApp: ${detail}`,
			reason: "discovery-document-invalid",
			stage: "assembleApp",
			details: { reason: "discovery-document-invalid", detail },
			cause: planning.error,
		});
	}
	const discoveryRoute =
		planning.outcome === "planned" ? discoveryRouteFor(planning.plan, RouterCtor) : null;
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

	// Pre-pass: post-apply route collision check. Catches collisions produced
	// by factory-generated routes that were opaque at validate-manifests time,
	// AND any module route colliding with the synthesized discovery route.
	checkMaterialisedRouteCollisions(allRoutes);

	// Step 1: Mount-order computation.
	const ordered = computeMountOrder(allRoutes);

	// Step 2: Construct router.
	const router: Router = RouterCtor();

	// CORS, FIRST: before every other middleware and every route.
	//
	// A preflight carries no `Authorization` and no body, so it must be answered
	// before anything that would inspect either; and a browser can read an error
	// response (the `400 invalid_grant` an SPA most needs to see) only if
	// `Access-Control-Allow-Origin` is set on the way IN, before a downstream
	// handler ends the response.
	//
	// Mounted on an ALLOWLIST of paths, deliberately the opposite polarity to the
	// sender-constraint mount below (core README, CORS). `corsMw` returns null
	// for an empty `cors.allowedOrigins`: no CORS headers, not even `Vary`.
	{
		const components = frozen.components as Record<string, unknown>;
		const config = components.config as
			| { cors?: { allowedOrigins?: unknown }; oauth?: { jwt?: { jwksPath?: unknown } } }
			| undefined;
		const configured = config?.cors?.allowedOrigins;
		const logger = components.logger as Logger | undefined;
		// Read through the shared shape normaliser rather than testing for an
		// array: `assembleApp` is a stage of its own and may be handed raw
		// config, where the documented `${?CORS_ALLOWED_ORIGINS}` is a
		// comma-separated string (the only way an environment variable carries
		// a list). An `Array.isArray` test would silently skip the middleware.
		const allowedOrigins = normalizeAllowedOrigins(configured);
		if (allowedOrigins.length > 0) {
			const mw = corsMw({
				allowedOrigins,
				// On the issuer the discovery route is served on: the oauth
				// module's `oauthTokenSettings` when the composition holds it.
				routes: browserFacingCorsRoutes(config ?? {}, corsIssuerOptions(components)),
				...(logger ? { logger } : {}),
			});
			if (mw !== null) router.use(mw);
		} else if (
			configured !== undefined &&
			configured !== null &&
			!Array.isArray(configured) &&
			typeof configured !== "string"
		) {
			// An array or a string that normalises to nothing is an operator
			// saying "no origins", which is CORS off and needs no comment. A
			// shape neither reader can interpret is a misconfiguration, and
			// staying silent about it is what this whole block is here to
			// stop.
			logger?.warn({ received: typeof configured }, "cors_allowed_origins_unreadable");
		}
	}

	// The paths the protected-resource sender-constraint middleware must NOT
	// run on. Everything else is guarded: the mount below is GLOBAL, not an
	// allowlist of token-accepting surfaces, because an allowlist must track
	// every module's mount points and leaves a module's new token-accepting
	// route unguarded by default. A global mount is safe because the
	// middleware judges only requests that present an access token: it passes
	// requests with no Authorization header, non-token schemes (`Basic` client
	// auth on the introspection endpoint, browser-redirect flows), tokens that
	// do not decode as JWTs, and unbound tokens.
	//
	// `/oauth/token` is deliberately exempt: it authenticates a *client*, has
	// no access token in play, and runs the token-endpoint binding profile
	// instead. The path is coupled to the bundled `oauthModule`'s mountPath;
	// see the NOTE on the `grantMiddleware` mount.
	const TOKEN_ENDPOINT_PATH = "/oauth/token";
	/** The token endpoint's one method (RFC 6749 §3.2). */
	const TOKEN_ENDPOINT_METHOD = "POST";

	// A POST to exactly `/oauth/token`, case-insensitive, with one optional
	// trailing slash: exactly what `tokenEndpointOnly` below admits. Not the
	// sub-tree beneath it nor another method: those get no token-endpoint
	// profile, so exempting them would leave them guarded by neither, and a
	// DPoP-bound token replayed there as a plain Bearer would be admitted.
	const isSenderConstraintExempt = (req: Request): boolean => {
		const lowered = req.path.toLowerCase();
		return (
			req.method === TOKEN_ENDPOINT_METHOD &&
			(lowered === TOKEN_ENDPOINT_PATH || lowered === `${TOKEN_ENDPOINT_PATH}/`)
		);
	};

	// `mw`, for the token endpoint alone: under
	// `router.use(TOKEN_ENDPOINT_PATH, tokenEndpointOnly(mw))` it runs only for
	// a POST whose `req.path` is `/` (`/oauth/token` or `/oauth/token/`, any
	// case) and passes every other request on. A `use` mount rather than a
	// route, so a contribution sees `req.path` `/`, `req.url` `/?<query>` and
	// `req.baseUrl` ending in `/oauth/token`. A bare `use` mount would also run
	// it for every sub-path and method, handing another module's route the
	// token endpoint's binding verdict and grant middleware.
	const tokenEndpointOnly =
		(mw: RequestHandler): RequestHandler =>
		(req, res, next) => {
			if (req.method !== TOKEN_ENDPOINT_METHOD || req.path !== "/") {
				next();
				return;
			}
			// Returned so Express 5's router forwards a rejection to `next`.
			return mw(req, res, next);
		};

	// Synthesize a SINGLE `tokenBindingMw` from the `tokenBindingMechanisms`
	// collector and mount it on `/oauth/token` BEFORE any other grant
	// middleware, for the token endpoint alone. Mechanism modules (DPoP, mTLS,
	// ...) contribute raw mechanisms; one composed middleware lets the
	// configured `DispatchPolicy` arbitrate across modules. See ADR
	// 2026-05-20-token-binding-first-class-abstraction. Null entries (disabled
	// by config) are filtered; with no mechanisms, nothing is synthesized.
	const mechanismCollector = frozen.registries.get("tokenBindingMechanisms") as
		| ListCollector<TokenBindingMechanism | null>
		| undefined;
	if (mechanismCollector !== undefined) {
		const mechanisms: TokenBindingMechanism[] = [];
		for (const m of mechanismCollector.values()) {
			if (m !== null) mechanisms.push(m);
		}
		if (mechanisms.length > 0) {
			// Core's own policy, for core's own extension point: read from the
			// configuration in every composition, never from a slot.
			const dispatchPolicy: DispatchPolicy = resolveTokenBindingSettings(
				(frozen.components as Record<string, unknown>).config,
			).dispatchPolicy;
			const logger = (frozen.components as Record<string, unknown>).logger as Logger | undefined;
			const composed = tokenBindingMw({ mechanisms, dispatchPolicy, logger });
			router.use(TOKEN_ENDPOINT_PATH, tokenEndpointOnly(composed));
		}
	}

	// Mount the protected-resource sender-constraint middleware. The
	// `/oauth/token` mount above establishes a binding a grant stamps into the
	// issued token's `cnf`; this one refuses a `cnf`-bearing token at every
	// surface that accepts an access token unless the matching
	// proof-of-possession arrives with it. Without it a stolen DPoP- or
	// mTLS-bound token replays as a plain Bearer.
	//
	// Mounted UNCONDITIONALLY, unlike the `/oauth/token` mount: access tokens
	// outlive a config change, so a deployment that removes its DPoP module
	// still has bound tokens in the wild. With no mechanisms the middleware
	// admits every unbound token and refuses every bound one: fail closed.
	//
	// Mounted GLOBALLY, before every route contribution, so routes from modules
	// core has never heard of are guarded the moment they mount (see the
	// exempt-path rationale above).
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
		if (isSenderConstraintExempt(req)) {
			next();
			return;
		}
		// Returned so Express 5's router forwards a rejection to `next`.
		return protectedResourceMw(req, res, next);
	});

	// Mount `grantMiddleware` contributions on `/oauth/token` AFTER the
	// synthesized tokenBindingMw above, for the token endpoint alone. The
	// bundled `oauthModule` mounts its sub-router at `/oauth`
	// (packages/oauth/src/module.mts), so these handlers fire before its
	// `/token` route handler, which the routes loop installs below. Null
	// returns (disabled by config) are skipped here; the collector still
	// records them for value-identity dedup with other contributions.
	//
	// NOTE: this mount path is coupled to the bundled `oauthModule`'s
	// mountPath. A downstream that re-mounts the OAuth router at a different
	// path must also wrap or replace this composition step.
	const grantMwCollector = frozen.registries.get("grantMiddleware") as
		| ListCollector<RequestHandler | null>
		| undefined;
	if (grantMwCollector !== undefined) {
		for (const mw of grantMwCollector.values()) {
			if (mw !== null) {
				router.use(TOKEN_ENDPOINT_PATH, tokenEndpointOnly(mw));
			}
		}
	}

	// Mount each route contribution in mount-index order. The synthesized
	// discovery route (when present) is in `ordered` like any other, so it mounts
	// here through the same path — no special-casing.
	for (const orderedRoute of ordered) {
		router.use(orderedRoute.contribution.mountPath, orderedRoute.contribution.handler as never);
	}

	// The router's own answer to an error a route let through (a body
	// parser's refusal, anything that escaped a handler), mounted LAST because
	// Express hands an error only to handlers mounted after the layer that
	// raised it. Without it the error falls to the host, by default Express's
	// final handler: an HTML page with the stack outside production. A request
	// no route answered still passes on to the host. See
	// `middleware/terminalError.mts`.
	router.use(
		terminalErrorHandler(
			((frozen.components as Record<string, unknown>).logger as Logger | undefined) ??
				consoleLogger,
		),
	);

	// Step 3: Construct AppHandle.
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

	// Freeze the whole AppHandle before returning.
	return Object.freeze(handle);
}
