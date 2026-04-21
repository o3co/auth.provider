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

import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	fullSectionsSchema,
	type Module,
	type ModuleContext,
} from "@o3co/auth-provider-core";
import type { RequestHandler, Router } from "express";
import type { PassportStatic } from "passport";
import { createOAuthRouter } from "./routes.mjs";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

const oauthConfigSchema = fullSectionsSchema.pick({
	endpoints: true,
});

export const oauthModule = (params: {
	clientRepository: ClientRepository;
	codeRepository: CodeRepository;
	express?: ExpressLike;
}): Module => ({
	name: "oauth",
	configSchema: oauthConfigSchema,
	async init(context: ModuleContext): Promise<void> {
		const config = context.config as AppConfig;

		// Resolve passport via pathResolver for client credential auth on introspect
		const { default: passport } = (await import(context.pathResolver("passport"))) as {
			default: PassportStatic;
		};

		// Resolve passport-oauth2-client-password for client credential strategy
		const { Strategy: ClientCredentialStrategy } = (await import(
			context.pathResolver("passport-oauth2-client-password")
		)) as { Strategy: new (...args: unknown[]) => unknown };

		// Register client credential strategy on this passport instance
		passport.use(
			new (
				ClientCredentialStrategy as new (
					verify: (
						clientId: string,
						clientSecret: string,
						done: (err: Error | null, client?: unknown) => void,
					) => void,
				) => unknown
			)(
				async (
					clientId: string,
					clientSecret: string,
					done: (err: Error | null, client?: unknown) => void,
				) => {
					try {
						const client = await params.clientRepository.authenticate(clientId, clientSecret);
						if (!client) {
							return done(null, false);
						}
						return done(null, client as unknown);
					} catch (cause) {
						return done(cause as Error);
					}
				},
			) as import("passport").Strategy,
		);

		// We need express-like factory for creating sub-router.
		// Use the express instance passed via params, or construct a minimal one.
		const express: ExpressLike =
			params.express ??
			(await (async () => {
				const mod = await import(context.pathResolver("express"));
				return mod.default as ExpressLike;
			})());

		const { router: oauthRouter } = await createOAuthRouter(express, {
			passport,
			registry: context.grantRegistry,
			config,
			clientRepository: params.clientRepository,
			codeRepository: params.codeRepository,
			keyStore: context.keyStore,
		});

		context.router.use("/oauth", oauthRouter);
	},
});
