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
	type BootStage,
	type BuilderContext,
	checkDeploymentMode,
	consoleLogger,
	defineModule,
	fullSectionsSchema,
	type ReplicaSafetyDeclaration,
	type SessionCookiePolicy,
} from "@o3co/auth-provider-core";
import session from "express-session";
import { createSessionCsrfTokenSigner } from "../csrf-token-signer.mjs";
import { guardCookieSession } from "../internal/cookieSession.mjs";
import {
	type SessionCookieConfigSlice,
	sessionCookiePolicyFrom,
	sessionCookieRefusal,
} from "../session-cookie-policy.mjs";
import { createSessionStoreFactory, registerBuiltinSessionStores } from "../store/factory.mjs";

/**
 * Module-level config schema: this module owns the `session` config slice via
 * `fullSectionsSchema.pick`. The boot planner composes the manifests'
 * configSchemas into the validated `config` slot before any factory runs.
 */
const sessionStoreConfigSchema = fullSectionsSchema.pick({
	session: true,
});

const MODULE_NAME = "session-store";

/**
 * What forks per replica when `session.storage.type = "memory"`. Quoted
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

/**
 * The session cookie `session` describes: the one express-session is given
 * and the `sessionCookiePolicy` slot holds. A section that yields none refuses
 * boot at `stage`, as a configuration value refused: `config-validation-failed`,
 * its one issue naming the `session.*` key.
 */
function sessionCookieOf(session: SessionCookieConfigSlice, stage: BootStage): SessionCookiePolicy {
	const refusal = sessionCookieRefusal(session);
	if (refusal !== undefined) {
		throw new BootError({
			stage,
			reason: "config-validation-failed",
			message: refusal.message,
			details: {
				reason: "config-validation-failed",
				issues: [{ code: "custom", path: ["session", refusal.key], message: refusal.message }],
				modules: [{ module: MODULE_NAME }],
			},
		});
	}
	return sessionCookiePolicyFrom(session);
}

function buildSessionStoreModule(replicaSafety: ReplicaSafetyDeclaration | undefined) {
	// Written type arguments infer nothing, so the section schema (none) and
	// the provided keys `authoritative` is typed against are written too.
	return defineModule<
		"config" | "deploymentMode",
		"lifecycleRegistrar" | "readinessRegistrar" | "logger",
		never,
		"sessionCookiePolicy" | "csrfTokenSigner"
	>({
		name: MODULE_NAME,
		configSchema: sessionStoreConfigSchema,
		// `deploymentMode`: memory storage is refused under `multi`, so a mode
		// read as absent must not lift that.
		requires: ["config", "deploymentMode"],
		// `logger` is optional: the redis client's error handler, and the
		// middleware's report of a store that cannot load or save a session,
		// fall back to consoleLogger when the composition wires no logger slot.
		optional: ["lifecycleRegistrar", "readinessRegistrar", "logger"],
		...(replicaSafety === undefined ? {} : { replicaSafety }),
		provides: {
			// The session cookie's attributes, for a module that sets a cookie of
			// its own beside the session's or sizes what must outlive a session:
			// this module owns the cookie, and the others require the slot instead
			// of reading `session.*`. They are the attributes express-session is
			// given below; the signing secret is not among them.
			sessionCookiePolicy: (deps) =>
				sessionCookieOf((deps.config as AppConfig).session, "materializeComponents"),
			// The CSRF token's signature, under a key derived from the secret this
			// module owns: the session module's guard and routes sign through it,
			// and neither the secret nor the key leaves the signer.
			csrfTokenSigner: (deps) =>
				createSessionCsrfTokenSigner((deps.config as AppConfig).session.secret),
		},
		// One source while this module is loaded: its route mounts the cookie
		// `session.*` describes, so an `overrideComponents` entry for the slot
		// would describe a cookie no browser is given; boot refuses it
		// (`authoritative-component-overridden`). A composition without the
		// module fills the slot itself.
		authoritative: ["sessionCookiePolicy"],
		contributes: {
			routes: [
				async (deps) => {
					const config = deps.config as AppConfig;
					const replicas = checkDeploymentMode(
						deps.deploymentMode,
						"session-store: deploymentMode",
					);
					const ctx: BuilderContext = {
						lifecycle: deps.lifecycleRegistrar,
						readiness: deps.readinessRegistrar,
						logger: deps.logger,
					};
					const factory = createSessionStoreFactory(ctx);
					registerBuiltinSessionStores(factory);
					const storageSlice = config.session.storage as { type: string } & Record<string, unknown>;
					// The static `sessionStoreModule` declares no `replicaSafety`
					// (the storage type is config), so it told the stage-1 guard
					// nothing: refuse the combination here, with the same reason,
					// rather than mount a per-process store. With
					// `sessionStoreModuleFor(config)` the guard refused before this.
					if (storageSlice.type === "memory" && replicas === "multi") {
						throw new BootError({
							stage: "applyContributions",
							reason: "replica-unsafe-adapter",
							message: `deployment.mode is "multi" but session.storage.type is "memory", which cannot be shared across replicas: ${MEMORY_STORE_REPLICA_SAFETY.reason}. Set session.storage.type = "redis", or set deployment.mode = "single".`,
							details: { reason: "replica-unsafe-adapter", modules: [MODULE_NAME] },
						});
					}
					// The cookie the sessionCookiePolicy slot holds, refused where the
					// slot is refused, whether or not a module requires it, and before
					// the store opens a connection.
					const cookie = sessionCookieOf(config.session, "applyContributions");
					const store = await factory.create({
						type: storageSlice.type,
						...((storageSlice[storageSlice.type] ?? {}) as Record<string, unknown>),
					});
					// A store error express-session would hand to `next(err)` is
					// answered by the guard: `503` when the session cannot be loaded,
					// one error line either way (`../internal/cookieSession.mts`).
					const middleware = session({
						name: cookie.name,
						secret: config.session.secret,
						resave: false,
						saveUninitialized: false,
						store,
						cookie: {
							path: "/",
							httpOnly: true,
							secure: cookie.secure,
							maxAge: cookie.maxAgeMs,
							sameSite: cookie.sameSite,
							domain: cookie.domain,
						},
					});
					// No `before` clause: see the mount-order contract on
					// `sessionStoreModule` below.
					return {
						id: "session-middleware",
						mountPath: "/",
						handler: guardCookieSession(middleware, deps.logger ?? consoleLogger),
					};
				},
			],
		},
	});
}

/**
 * The session-store module built for one config.
 *
 * `session.storage.type = "memory"` is express-session's per-process
 * `MemoryStore`, the same shape as every memory store the replica-safety guard
 * refuses under `deployment.mode = "multi"`, but the type is config, so a
 * static manifest cannot carry the declaration. This declares `replicaSafety`
 * when the configured store is in memory, so the guard refuses it by name
 * under `"multi"`, warns when the mode is unset, and says nothing under
 * `"single"`. Every other adapter is a shared store and declares nothing.
 *
 * Prefer this over {@link sessionStoreModule} wherever the config is in hand
 * at composition time, as in the standalone's `buildModules(config)`.
 */
export function sessionStoreModuleFor(config: SessionStoreModuleConfig) {
	return buildSessionStoreModule(
		storageTypeOf(config) === "memory" ? MEMORY_STORE_REPLICA_SAFETY : undefined,
	);
}

/**
 * The static session-store manifest: the express-session middleware as a
 * route at `mountPath: "/"`, built in the boot planner's DI graph so the
 * store's client receives a `BuilderContext.lifecycle` and can register
 * `client.quit()` for disposal.
 *
 * **Mount-order contract**: the route has no `before` / `after` clause,
 * because naming an absent route id raises a `route-order-target-missing`
 * BootError on partial manifests (e.g. an oauth-only deployment without
 * `sessionModule`). Order comes from declarationIndex tie-breaking: the
 * composition root MUST list this module ahead of every session-consuming
 * module in `buildModules(config)` (README, "Browser session store").
 *
 * It does not know the storage type, so it declares no `replicaSafety` and the
 * stage-1 guard cannot name it. The route factory still refuses `memory` when
 * the `deploymentMode` slot is `multi`, but a composition root that has its
 * config should use {@link sessionStoreModuleFor} and get the refusal at stage
 * 1, listed with the other offenders.
 */
export const sessionStoreModule = buildSessionStoreModule(undefined);
