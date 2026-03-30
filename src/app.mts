/*
 * Copyright 2026 1o1 Inc.
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
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { RedisStore } from "connect-redis";
import express from "express";
import session from "express-session";
import helmet from "helmet";
import { createClient } from "redis";

import { type AppConfig, AppConfigSchema } from "../config/application.schema.mjs";
import { ClientFactory } from "./clients/ClientFactory.mjs";
import logger from "./logger.mjs";
import { createPassport } from "./Passport.mjs";
import { createRouter } from "./routes/index.mjs";

const config: AppConfig = validate(
	parseFile(new URL("../config/application.conf", import.meta.url).pathname),
	AppConfigSchema,
);

// eslint-disable-next-line @typescript-eslint/no-floating-promises
await (async (): Promise<void> => {
	const clients = new ClientFactory({
		User: new (await import("./clients/User.mjs")).UserClient(config.clients.user),
		Client: new (await import("./clients/Client.mjs")).AppClient(config.clients.client),
		code: new (await import("./clients/Code.mjs")).CodeClient(config.clients.code),
	});

	await clients.initialize();

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

	const storageType = config.session.storage.type;
	let store: session.Store | undefined;
	switch (storageType) {
		case "redis":
			{
				const options = config.session.storage.redis;
				const redisClient = createClient({ url: options.url, password: options.password });
				await redisClient.connect();
				store = new RedisStore({ client: redisClient });
			}
			break;
		case "memory":
			store = undefined; // Use default in-memory store
			break;
		default:
			throw new Error(`Unsupported session storage type: ${storageType}`);
	}

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

	// Initialize Passport
	const passport = await createPassport({ clients, config });

	app.use(passport.initialize());
	app.use(passport.session());

	// Initialize Routes with DI
	const { router, grantRegistry } = createRouter(express, { passport, config, clients });
	app.use(router);

	const server = app.listen(config.http.port, (): void => {
		logger.info(`Server is running on http://localhost:${config.http.port}`);
	});

	const shutdown = (): void => {
		grantRegistry.cleanup();
		server.close(() => process.exit(0));
	};
	process.on("SIGTERM", shutdown);
	process.on("SIGINT", shutdown);
})();
