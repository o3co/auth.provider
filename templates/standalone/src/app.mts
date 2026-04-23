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
import path from "node:path";
import { fileURLToPath } from "node:url";
import { gracefulShutdown } from "@o3co/auth.utils";
import {
	type AppConfig,
	AppConfigSchema,
	createApp,
	createDefaultFactories,
	createFederationTokenStoreFactory,
	createKeyStoreFactory,
	createUserSessionStoreFactory,
	registerBuiltinFederationTokenStores,
	registerBuiltinKeyStores,
	registerBuiltinUserSessionStores,
} from "@o3co/auth-provider-core";
import { registerGoogleFederation } from "@o3co/auth-provider-federation-google";
// import { registerGithubFederation } from "@o3co/auth-provider-federation-github";
import { registerBuiltinAdapters } from "@o3co/auth-provider-foundation";
import {
	oauthAuthorizationModule,
	oauthModule,
	oauthSessionModule,
} from "@o3co/auth-provider-oauth";
import {
	createFederationProviderFactory,
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

// Step 1: Load and validate application config (HOCON → Zod schema).
// Layering: {ENV}.conf overrides application.conf.
// ENV = CONFIG_ENV || NODE_ENV || "development". A missing {ENV}.conf is a
// boot-time error (fail-fast on typos or unconfigured environments).
const env = process.env.CONFIG_ENV || process.env.NODE_ENV || "development";
const configDir = new URL("../config/", import.meta.url);
const configDirPath = fileURLToPath(configDir);
const { applicationConfPath, envConfPath } = resolveConfigPaths(configDirPath, env);
const config: AppConfig = validate(
	parseFile(envConfPath).withFallback(parseFile(applicationConfPath)),
	AppConfigSchema,
);

const flattenAdapterConfig = (
	section: ({ type: string } | { provider: string }) & Record<string, unknown>,
): { type: string } & Record<string, unknown> => {
	const selector =
		(section as { type?: string; provider?: string }).type ??
		(section as { provider?: string }).provider;
	if (typeof selector !== "string") {
		throw new TypeError("flattenAdapterConfig: section requires 'type' or 'provider' string");
	}
	const sub = section[selector];
	const flattenedSub =
		typeof sub === "object" && sub !== null && !Array.isArray(sub)
			? (sub as Record<string, unknown>)
			: {};
	return { type: selector, ...flattenedSub };
};

await (async (): Promise<void> => {
	// Step 2: Build repository factories and register built-in adapters (memory / file / etc.).
	const appDir = path.dirname(fileURLToPath(import.meta.url));
	const { clientFactory, userFactory, codeFactory } = createDefaultFactories();
	registerBuiltinAdapters({ userFactory, codeFactory, pathResolver: import.meta.resolve });

	// Step 3: Instantiate client / user / code repositories from config.
	const clientConfig = flattenAdapterConfig(
		config.repositories.client as { type: string } & Record<string, unknown>,
	);
	if (typeof clientConfig.path === "string") {
		clientConfig.path = path.resolve(appDir, "..", clientConfig.path);
	}
	const clientRepository = await clientFactory.create(clientConfig);
	const userRepository = await userFactory.create(
		flattenAdapterConfig(config.repositories.user as { type: string } & Record<string, unknown>),
	);
	const codeRepository = await codeFactory.create(
		flattenAdapterConfig(config.repositories.code as { type: string } & Record<string, unknown>),
	);

	// Step 4: Create the Express app and apply base security middleware (trust proxy + helmet).
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

	// Step 5: Build the session store from config and mount express-session middleware.
	const sessionStoreFactory = createSessionStoreFactory();
	registerBuiltinSessionStores(sessionStoreFactory);
	const store = await sessionStoreFactory.create(
		flattenAdapterConfig(config.session.storage as { type: string } & Record<string, unknown>),
	);

	app.use(
		session({
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
		}),
	);

	// Step 6: Build the JWT signing KeyStore used to issue access / ID tokens.
	const keyStoreFactory = createKeyStoreFactory();
	registerBuiltinKeyStores(keyStoreFactory);
	const keyStore = await keyStoreFactory.create(flattenAdapterConfig(config.oauth.jwt.signingKey));

	// Step 7: Build UserSessionStore and FederationTokenStore (required by sessionModule).
	const userSessionStoreFactory = createUserSessionStoreFactory();
	registerBuiltinUserSessionStores(userSessionStoreFactory);
	const userSessionStore = await userSessionStoreFactory.create(
		flattenAdapterConfig(
			(config as { userSessionStore?: { type: string } & Record<string, unknown> })
				.userSessionStore ?? { type: "memory" },
		),
	);

	const federationTokenStoreFactory = createFederationTokenStoreFactory();
	registerBuiltinFederationTokenStores(federationTokenStoreFactory);
	const federationTokenStore = await federationTokenStoreFactory.create(
		flattenAdapterConfig(
			(config as { federationTokenStore?: { type: string } & Record<string, unknown> })
				.federationTokenStore ?? { type: "memory" },
		),
	);

	const federationProviderFactory = createFederationProviderFactory();
	registerGoogleFederation(federationProviderFactory);
	// registerGithubFederation(federationProviderFactory);

	// Step 8: Compose the OAuth / session modules and build the app router.
	const { init, router, grantRegistry } = createApp({
		express,
		pathResolver: import.meta.resolve,
		config,
		keyStore,
		userSessionStore,
		federationTokenStore,
		modules: [
			oauthModule({ clientRepository, codeRepository, express }),
			sessionModule({ userRepository, express, federationProviderFactory }),
			oauthSessionModule({ clientRepository }),
			oauthAuthorizationModule({ codeRepository, clientRepository }),
		],
	});

	// Step 9: Run async module init (resolves external deps via pathResolver).
	await init();

	// Step 10: Mount the composed router onto the Express app.
	app.use(router);

	// Step 11: Start the HTTP server.
	const server = app.listen(config.http.port, (): void => {
		logger.info(`Server is running on http://localhost:${config.http.port}`);
	});

	// Step 12: Register graceful shutdown so in-flight grants are cleaned up on SIGTERM / SIGINT.
	gracefulShutdown(server, () => grantRegistry.cleanup());
})();
