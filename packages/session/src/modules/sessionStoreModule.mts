/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import {
	type AppConfig,
	BootError,
	type BuilderContext,
	defineModule,
	fullSectionsSchema,
	type ReplicaSafetyDeclaration,
} from "@o3co/auth-provider-core";
import session from "express-session";
import { createSessionStoreFactory, registerBuiltinSessionStores } from "../store/factory.mjs";

/**
 * Module-level config schema: this module owns the `session` config slice via
 * `fullSectionsSchema.pick`. The boot planner composes the manifests'
 * configSchemas into the validated `config` slot before any factory runs.
 */
const sessionStoreConfigSchema = fullSectionsSchema.pick({
	session: true,
});

const MODULE_NAME = "sessionStoreModule";

/**
 * What forks per replica when `session.storage.type = "memory"` (#474). Quoted
 * by the replica-safety guard into a refused boot and into the unset-mode
 * warning, so it names the consequence rather than the fix.
 */
const MEMORY_STORE_REPLICA_SAFETY: ReplicaSafetyDeclaration = {
	unsafe: true,
	reason:
		"the express-session store forks per replica — a login served by one replica is unknown to the others, so a browser whose next request lands elsewhere is logged out, logout clears only the session the replica it lands on can see, and every session is lost on restart",
};

/** The slice of config this module's manifest is built from. */
export interface SessionStoreModuleConfig {
	readonly session?: { readonly storage?: { readonly type?: unknown } };
}

const storageTypeOf = (config: SessionStoreModuleConfig | undefined): unknown =>
	config?.session?.storage?.type;

function buildSessionStoreModule(replicaSafety: ReplicaSafetyDeclaration | undefined) {
	return defineModule<"config", "lifecycleRegistrar" | "readinessRegistrar" | "logger">({
		name: MODULE_NAME,
		configSchema: sessionStoreConfigSchema,
		requires: ["config"],
		// `logger` is optional (D-4): the redis client's error handler falls back
		// to consoleLogger when the composition wires no logger slot.
		optional: ["lifecycleRegistrar", "readinessRegistrar", "logger"],
		...(replicaSafety === undefined ? {} : { replicaSafety }),
		contributes: {
			routes: [
				async (deps) => {
					const config = deps.config as AppConfig;
					const ctx: BuilderContext = {
						lifecycle: deps.lifecycleRegistrar,
						readiness: deps.readinessRegistrar,
						logger: deps.logger,
					};
					const factory = createSessionStoreFactory(ctx);
					registerBuiltinSessionStores(factory);
					const storageSlice = config.session.storage as { type: string } & Record<string, unknown>;
					// #474: the static manifest (`sessionStoreModule`) declares no
					// `replicaSafety` because the storage type is config, and this
					// is the first point at which it is known for certain. A
					// composition root that wired the static manifest under
					// `deployment.mode = "multi"` has told the stage-1 guard
					// nothing, so the same combination is refused here, with the
					// same reason, rather than mounting a per-process store. With
					// `sessionStoreModuleFor(config)` the guard has already refused
					// before this runs.
					if (storageSlice.type === "memory" && config.deployment?.mode === "multi") {
						throw new BootError({
							stage: "applyContributions",
							reason: "replica-unsafe-adapter",
							message: `deployment.mode is "multi" but session.storage.type is "memory", which cannot be shared across replicas: ${MEMORY_STORE_REPLICA_SAFETY.reason}. Set session.storage.type = "redis", or set deployment.mode = "single".`,
							details: { reason: "replica-unsafe-adapter", modules: [MODULE_NAME] },
						});
					}
					if (
						config.session.name.startsWith("__Host-") &&
						(config.session.secure !== true || config.session.domain !== null)
					) {
						throw new Error(
							"session.name with __Host- prefix requires session.secure=true and session.domain=null",
						);
					}
					const store = await factory.create({
						type: storageSlice.type,
						...((storageSlice[storageSlice.type] ?? {}) as Record<string, unknown>),
					});
					const middleware = session({
						name: config.session.name,
						secret: config.session.secret,
						resave: false,
						saveUninitialized: false,
						store,
						cookie: {
							path: "/",
							httpOnly: true,
							secure: config.session.secure,
							maxAge: config.session.maxAge,
							sameSite: config.session.sameSite,
							domain: config.session.domain || undefined,
						},
					});
					// Mount-order contract (D-5): no `before` clause, because
					// `before: ["...absent..."]` raises a `route-order-target-missing`
					// BootError when the consumer omits the named module (e.g. an
					// oauth-only deployment that doesn't include sessionModule).
					// Instead, the middleware relies on declarationIndex tie-breaking:
					// the composition root MUST list `sessionStoreModule` ahead of
					// every session-consuming module in `buildModules(...)`. The
					// standalone template puts it first; documented in the
					// v0.5.1 CHANGELOG migration note.
					return {
						id: "session-middleware",
						mountPath: "/",
						handler: middleware,
					};
				},
			],
		},
	});
}

/**
 * The session-store module built for one config (#474).
 *
 * `session.storage.type = "memory"` is express-session's own per-process
 * `MemoryStore` — the same shape as every memory store the replica-safety
 * guard refuses under `deployment.mode = "multi"` (#271, #455), but the type is
 * config, so a static manifest cannot carry the declaration. This reads it off
 * the config the composition root already holds and returns the manifest with
 * `replicaSafety` declared when the store is in memory, so the guard refuses
 * `SESSION_STORAGE_TYPE=memory` under `"multi"` by name, warns when the mode is
 * unset, and says nothing under `"single"` — exactly as for the other stores.
 * Every other adapter is a shared store and declares nothing.
 *
 * Prefer this over {@link sessionStoreModule} wherever the config is in hand
 * at composition time — the standalone's `buildModules(config)` is.
 */
export function sessionStoreModuleFor(config: SessionStoreModuleConfig) {
	return buildSessionStoreModule(
		storageTypeOf(config) === "memory" ? MEMORY_STORE_REPLICA_SAFETY : undefined,
	);
}

/**
 * D-5 / OR-M2: `sessionStoreModule` moves the express-session middleware
 * construction (previously inlined in `templates/standalone/src/app.mts`) into
 * the boot planner's DI graph so the underlying session-store client receives
 * a `BuilderContext.lifecycle` and can register `client.quit()` for disposal.
 *
 * The module contributes a route at `mountPath: "/"` whose handler is the
 * express-session RequestHandler. **Mount-order contract**: the route
 * intentionally has NO `before`/`after` clause, because referencing absent
 * downstream route ids would raise `route-order-target-missing` BootError on
 * partial manifests (e.g. an oauth-only deployment without sessionModule).
 * Mount order is enforced by **declarationIndex tie-breaking** — the
 * composition root MUST list `sessionStoreModule` ahead of every
 * session-consuming module in `buildModules(config)`.
 *
 * Standalone composition root: drop the manual `app.use(session(...))` block
 * and prepend `sessionStoreModule` to `buildModules(config)`. The session
 * middleware is mounted inside `handle.router`, ordered first by list
 * position. See CHANGELOG v0.5.1 D-5 BREAKING entry for the migration note.
 *
 * This is the static manifest: it does not know the storage type, so it
 * declares no `replicaSafety` and the stage-1 guard cannot name it. The route
 * factory still refuses `memory` under `deployment.mode = "multi"` (#474), so
 * the combination cannot boot either way — but a composition root that has
 * its config should use {@link sessionStoreModuleFor} and get the refusal at
 * stage 1, listed with the other offenders.
 */
export const sessionStoreModule = buildSessionStoreModule(undefined);
