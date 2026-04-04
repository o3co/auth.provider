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

import type { AppConfig } from "#/config/application.schema.mjs";
import { GrantRegistry } from "#/grants/registry.mjs";
import type { KeyStore } from "#/keys/KeyStore.mjs";
import type { ClientRepository } from "#/repositories/ClientRepository.mjs";
import type { CodeRepository } from "#/repositories/CodeRepository.mjs";
import type { UserRepository } from "#/repositories/UserRepository.mjs";
import type { Module, ModuleContext, PathResolver } from "#/modules/types.mjs";
import * as healthcheck from "#/routes/Healthcheck.mjs";
import * as jwks from "#/routes/Jwks.mjs";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

export interface AppOptions {
	pathResolver?: PathResolver;
	config: AppConfig;
	keyStore: KeyStore;
	modules: Module[];
	clientRepository: ClientRepository;
	codeRepository: CodeRepository;
	userRepository?: UserRepository;
}

export interface AppResult {
	init(): Promise<void>;
	router: Router;
	grantRegistry: GrantRegistry;
}

export function createApp(express: ExpressLike, options: AppOptions): AppResult {
	const {
		pathResolver = (s: string) => s,
		config,
		keyStore,
		modules,
	} = options;

	const router = express.Router();
	const grantRegistry = new GrantRegistry();

	// Wire core infrastructure routes (pure — no external deps)
	router
		.use(healthcheck.createRouter(express))
		.use(jwks.createRouter(express, keyStore));

	const context: ModuleContext = {
		pathResolver,
		config,
		keyStore,
		grantRegistry,
		router,
	};

	async function init(): Promise<void> {
		for (const module of modules) {
			await module.init(context);
		}
	}

	return { init, router, grantRegistry };
}
