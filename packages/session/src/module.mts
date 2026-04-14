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

import type { AppConfig, Module, ModuleContext, UserRepository } from "@o3co/auth-provider-core";
import type { RequestHandler, Router } from "express";
import { createGoogleProvider } from "./federations/google.mjs";
import { FederationRegistry } from "./federations/types.mjs";
import { createPassport } from "./passport.mjs";
import * as federationRoutes from "./routes/Federation.mjs";
import * as sessionRoutes from "./routes/Session.mjs";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

export const sessionModule = (params: {
	userRepository: UserRepository;
	express?: ExpressLike;
}): Module => ({
	name: "session",
	async init(context: ModuleContext): Promise<void> {
		const express: ExpressLike =
			params.express ??
			(await (async () => {
				const mod = await import(context.pathResolver("express"));
				return mod.default as ExpressLike;
			})());
		const config = context.config as AppConfig;

		// Initialize passport with pathResolver
		const passport = await createPassport({
			pathResolver: context.pathResolver,
			userRepository: params.userRepository,
			config,
		});

		// Build federation registry
		const federationRegistry = new FederationRegistry();
		federationRegistry.register(createGoogleProvider(config));

		// Mount session routes
		context.router.use(
			"/session",
			sessionRoutes.createRouter(express, {
				passport,
				config,
			}),
		);

		// Mount federation routes
		context.router.use(
			"/session",
			federationRoutes.createRouter(express, {
				passport,
				config,
				federationRegistry,
			}),
		);
	},
});
