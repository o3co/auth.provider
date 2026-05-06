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
import {
	createSessionStoreFactory,
	registerBuiltinSessionStores,
} from "../store/factory.mjs";

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
 * express-session RequestHandler. The route declares `before` against every
 * downstream route id so the middleware initialises `req.session` for them
 * (session-routes / federation-routes / oauth-endpoints — extend the list if
 * a future module adds another top-level route id).
 *
 * Standalone composition root: drop the manual `app.use(session(...))` block
 * and add `sessionStoreModule` to `buildModules(config)`. The session
 * middleware is then mounted inside `handle.router`, ordered first via the
 * `before` clause.
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
				const storageSlice = config.session.storage as { type: string } & Record<
					string,
					unknown
				>;
				const store = await factory.create({
					type: storageSlice.type,
					...((storageSlice[storageSlice.type] ?? {}) as Record<string, unknown>),
				});
				const middleware = session({
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
				return {
					id: "session-middleware",
					mountPath: "/",
					handler: middleware,
					// Mount BEFORE every downstream top-level route so they observe
					// `req.session`. Add additional ids here when new top-level
					// routes are introduced.
					before: ["session-routes", "federation-routes", "oauth-endpoints"],
				};
			},
		],
	},
});
