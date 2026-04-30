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
import { fileURLToPath } from "node:url";
import { gracefulShutdown } from "@o3co/auth.utils";
import { type AppConfig, AppConfigSchema, createApp } from "@o3co/auth-provider-core";
import { googleFederationModule } from "@o3co/auth-provider-federation-google";
import {
	oauthAuthorizationModule,
	oauthModule,
	oauthSessionModule,
} from "@o3co/auth-provider-oauth";
import {
	createSessionStoreFactory,
	registerBuiltinSessionStores,
	sessionModule,
} from "@o3co/auth-provider-session";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import express from "express";
import session from "express-session";
import helmet from "helmet";

import logger from "#/logger.mjs";
import { resolveConfigPaths } from "./configPath.mjs";
import {
	googleFederationConfigModule,
	keyStoreModule,
	repositoriesModule,
	storesModule,
} from "./modules.mjs";

// Step 1: Load and validate application config (HOCON → Zod schema).
// ENV = CONFIG_ENV || NODE_ENV || "development"; missing {ENV}.conf is fatal.
const env = process.env.CONFIG_ENV || process.env.NODE_ENV || "development";
const configDir = new URL("../config/", import.meta.url);
const configDirPath = fileURLToPath(configDir);
const { applicationConfPath, envConfPath } = resolveConfigPaths(configDirPath, env);
const config: AppConfig = validate(
	parseFile(envConfPath).withFallback(parseFile(applicationConfPath)),
	AppConfigSchema,
);

await (async (): Promise<void> => {
	// Step 2: Create the Express app and apply base security middleware.
	const app = express();
	app.set("trust proxy", config.http.trustProxy);
	app.use(
		helmet({
			contentSecurityPolicy: {
				directives: {
					defaultSrc: ["'none'"],
					frameAncestors: ["'none'"],
				},
			},
		}),
	);

	// Step 3: Build the Express session store and mount express-session.
	// (express-session is host-environment middleware, not part of the auth
	// boot pipeline — wired before createApp so it sits ahead of the router.)
	const sessionStoreFactory = createSessionStoreFactory();
	registerBuiltinSessionStores(sessionStoreFactory);
	const sessionStorageSlice = config.session.storage as {
		type: string;
	} & Record<string, unknown>;
	const sessionStore = await sessionStoreFactory.create({
		type: sessionStorageSlice.type,
		...((sessionStorageSlice[sessionStorageSlice.type] ?? {}) as Record<string, unknown>),
	});
	app.use(
		session({
			secret: config.session.secret,
			resave: false,
			saveUninitialized: false,
			store: sessionStore,
			cookie: {
				path: "/",
				httpOnly: true,
				secure: config.session.secure,
				maxAge: config.session.maxAge,
				sameSite: config.session.sameSite,
				domain: config.session.domain || undefined,
			},
		}),
	);

	// Step 4: Boot the auth pipeline. bootstrapComponents carries only host-
	// environment values (config + pathResolver per A2-γ §4 worked example);
	// every other component flows through composition-root-local modules.
	const handle = await createApp({
		modules: [
			oauthModule({ config }),
			oauthSessionModule({ config }),
			oauthAuthorizationModule({ config }),
			sessionModule,
			googleFederationModule,
			googleFederationConfigModule,
			keyStoreModule,
			repositoriesModule,
			storesModule,
		],
		bootstrapComponents: {
			config,
			pathResolver: import.meta.resolve,
		},
	});

	// Step 5: Wire host-level routes (healthcheck) before the auth router so
	// they remain reachable even when the auth pipeline is degraded.
	app.get("/_healthcheck", (_req, res) => {
		res.status(200).json({ status: "ok" });
	});

	// Step 6: Mount the composed auth router and start the HTTP server.
	app.use(handle.router);
	const server = app.listen(config.http.port, (): void => {
		logger.info(`Server is running on http://localhost:${config.http.port}`);
	});

	// Step 7: Graceful shutdown — handle.dispose() runs reverse-topological
	// per-component cleanup (per A2-β §8.1). Replaces the v0.4.x
	// grantRegistry.cleanup() bridge.
	gracefulShutdown(server, () => handle.dispose());
})();
