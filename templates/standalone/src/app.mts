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
	createKeyStoreFromConfig,
} from "@o3co/auth-provider-core";
import { registerBuiltinAdapters } from "@o3co/auth-provider-foundation";
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
import passport from "passport";

import logger from "#/logger.mjs";

const config: AppConfig = validate(
	parseFile(fileURLToPath(new URL("../config/application.conf", import.meta.url))),
	AppConfigSchema,
);

const flattenAdapterConfig = (
	section: { type: string } & Record<string, unknown>,
): { type: string } & Record<string, unknown> => {
	const sub = section[section.type];
	const flattenedSub =
		typeof sub === "object" && sub !== null && !Array.isArray(sub)
			? (sub as Record<string, unknown>)
			: {};
	return { type: section.type, ...flattenedSub };
};

await (async (): Promise<void> => {
	// Initialize repositories via factory
	const appDir = path.dirname(fileURLToPath(import.meta.url));
	const { clientFactory, userFactory, codeFactory } = createDefaultFactories();
	registerBuiltinAdapters({ userFactory, codeFactory, pathResolver: import.meta.resolve });

	const clientConfig = flattenAdapterConfig(
		config.clients.client as { type: string } & Record<string, unknown>,
	);
	if (typeof clientConfig.path === "string") {
		clientConfig.path = path.resolve(appDir, "..", clientConfig.path);
	}
	const clientRepository = await clientFactory.create(clientConfig);
	const userRepository = await userFactory.create(
		flattenAdapterConfig(config.clients.user as { type: string } & Record<string, unknown>),
	);
	const codeRepository = await codeFactory.create(
		flattenAdapterConfig(config.clients.code as { type: string } & Record<string, unknown>),
	);

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

	// Initialize Passport middleware (strategies are registered by modules during init)
	app.use(passport.initialize());
	app.use(passport.session());

	// Initialize KeyStore
	const keyStore = await createKeyStoreFromConfig(config.oauth.jwt);

	// Create app with module composition
	const { init, router, grantRegistry } = createApp({
		express,
		pathResolver: import.meta.resolve,
		config,
		keyStore,
		modules: [
			oauthModule({ clientRepository, codeRepository, express }),
			sessionModule({ userRepository, express }),
			oauthSessionModule({ clientRepository }),
			oauthAuthorizationModule({ codeRepository, clientRepository }),
		],
	});

	// Initialize all modules (async — resolves external deps via pathResolver)
	await init();

	app.use(router);

	const server = app.listen(config.http.port, (): void => {
		logger.info(`Server is running on http://localhost:${config.http.port}`);
	});

	gracefulShutdown(server, () => grantRegistry.cleanup());
})();
