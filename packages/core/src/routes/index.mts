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
import type { PassportStatic } from "passport";
import type { AppConfig } from "#/config/application.schema.mjs";
import { createGoogleProvider } from "#/federations/google.mjs";
import { FederationRegistry } from "#/federations/types.mjs";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";
import { GrantRegistry } from "#/grants/registry.mjs";
import { createSessionGrant } from "#/grants/session.mjs";
import type { KeyStore } from "#/keys/KeyStore.mjs";
import type { ClientRepository } from "#/repositories/ClientRepository.mjs";
import type { CodeRepository } from "#/repositories/CodeRepository.mjs";
import * as federation from "./Federation.mjs";
import * as healthcheck from "./Healthcheck.mjs";
import * as jwks from "./Jwks.mjs";
import * as oauth from "./OAuth.mjs";
import * as session from "./Session.mjs";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

type RouterParams = {
	passport: PassportStatic;
	config: AppConfig;
	keyStore: KeyStore;
	clientRepository: ClientRepository;
	codeRepository: CodeRepository;
};

export const createRouter = (
	express: ExpressLike,
	params: RouterParams,
): { router: Router; grantRegistry: GrantRegistry } => {
	const router = express.Router();

	// Create grant registry and wire built-in grant handlers
	const grantRegistry = new GrantRegistry();
	const deps = { config: params.config, keyStore: params.keyStore };
	grantRegistry.register("session", createSessionGrant({ ...deps, clientRepository: params.clientRepository }));
	grantRegistry.register("authorization", createAuthorizationGrant({ ...deps, codeRepository: params.codeRepository }));
	grantRegistry.register("refresh_token", createRefreshTokenGrant(deps));

	const { router: oauthRouter } = oauth.createRouter(express, {
		passport: params.passport,
		registry: grantRegistry,
		config: params.config,
		clientRepository: params.clientRepository,
		codeRepository: params.codeRepository,
		keyStore: params.keyStore,
	});

	// Build federation registry
	const federationRegistry = new FederationRegistry();
	federationRegistry.register(createGoogleProvider(params.config));

	router
		.use(healthcheck.createRouter(express))
		.use(jwks.createRouter(express, params.keyStore))
		.use("/oauth", oauthRouter)
		.use(
			"/session",
			session.createRouter(express, { passport: params.passport, config: params.config }),
		)
		.use(
			"/session",
			federation.createRouter(express, {
				passport: params.passport,
				config: params.config,
				federationRegistry,
			}),
		);

	return { router, grantRegistry };
};
