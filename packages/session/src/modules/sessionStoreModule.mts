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
	type BuilderContext,
	defineModule,
	fullSectionsSchema,
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
 */
export const sessionStoreModule = defineModule<"config", "lifecycleRegistrar">({
	name: "sessionStoreModule",
	configSchema: sessionStoreConfigSchema,
	requires: ["config"],
	optional: ["lifecycleRegistrar"],
	contributes: {
		routes: [
			async (deps) => {
				const config = deps.config as AppConfig;
				const ctx: BuilderContext = { lifecycle: deps.lifecycleRegistrar };
				const factory = createSessionStoreFactory(ctx);
				registerBuiltinSessionStores(factory);
				const storageSlice = config.session.storage as { type: string } & Record<string, unknown>;
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
