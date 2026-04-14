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
import type { RequestHandler, Router } from "express";
import type { z } from "zod";
import type { CoreConfig } from "./config/application.schema.mjs";
import { composeConfigSchema } from "./config/application.schema.mjs";
import { GrantRegistry } from "./grants/registry.mjs";
import type { KeyStore } from "./keys/KeyStore.mjs";
import type { Module, ModuleContext, PathResolver } from "./modules/types.mjs";
import * as healthcheck from "./routes/Healthcheck.mjs";
import * as jwks from "./routes/Jwks.mjs";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

export interface AppOptions {
	express?: ExpressLike;
	pathResolver?: PathResolver;
	config: CoreConfig & Record<string, unknown>;
	keyStore: KeyStore;
	modules: Module[];
}

export interface AppResult {
	init(): Promise<void>;
	router: Router;
	grantRegistry: GrantRegistry;
}

export function createApp(options: AppOptions): AppResult {
	const { pathResolver = (s: string) => s, config, keyStore, modules } = options;

	const express: ExpressLike =
		options.express ??
		(() => {
			throw new Error(
				"express must be provided in AppOptions or resolved via pathResolver before createApp is called",
			);
		})();

	const router = express.Router();
	const grantRegistry = new GrantRegistry();

	// Wire core infrastructure routes (pure — no external deps)
	router.use(healthcheck.createRouter(express)).use(jwks.createRouter(express, keyStore));

	const context: ModuleContext = {
		pathResolver,
		config,
		keyStore,
		grantRegistry,
		router,
	};

	async function init(): Promise<void> {
		const moduleSchemas = modules
			.map((m) => m.configSchema)
			.filter((s): s is z.ZodObject<z.ZodRawShape> => s !== undefined);
		const validatedConfig = composeConfigSchema(moduleSchemas).parse(config);
		context.config = validatedConfig as CoreConfig & Record<string, unknown>;

		for (const module of modules) {
			await module.init(context);
		}
	}

	return { init, router, grantRegistry };
}
