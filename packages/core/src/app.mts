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
import type { AuditSinkBase } from "./audit/types.mjs";
import type { CoreConfig } from "./config/application.schema.mjs";
import { composeConfigSchema } from "./config/application.schema.mjs";
import { GrantRegistry } from "./grants/registry.mjs";
import type { KeyStore } from "./keys/KeyStore.mjs";
import type { MfaCoordinator, MfaProviderFactory, MfaTransactionStore } from "./mfa/types.mjs";
import type { Module, ModuleContext, PathResolver } from "./modules/types.mjs";
import type { GrantPolicyHookBase } from "./policy/types.mjs";
import type { RateLimiterBase } from "./ratelimit/types.mjs";
import type { RefreshTokenStoreBase } from "./refresh/types.mjs";
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
	mfaProviderFactory?: MfaProviderFactory;
	mfaCoordinator?: MfaCoordinator;
	mfaTransactionStore?: MfaTransactionStore;
	auditSink?: AuditSinkBase;
	rateLimiter?: RateLimiterBase;
	refreshTokenStore?: RefreshTokenStoreBase;
	grantPolicy?: GrantPolicyHookBase;
}

export interface AppResult {
	init(): Promise<void>;
	router: Router;
	grantRegistry: GrantRegistry;
}

export function createApp(options: AppOptions): AppResult {
	const { pathResolver = (s: string) => s, config, keyStore, modules } = options;

	if (options.mfaCoordinator) {
		if (!options.mfaProviderFactory) {
			throw new Error("createApp: mfaProviderFactory is required when mfaCoordinator is set");
		}
		if (!options.mfaTransactionStore) {
			throw new Error("createApp: mfaTransactionStore is required when mfaCoordinator is set");
		}
	}

	// CP-20: when grantPolicy is configured, config.oauth.jwt.issuer MUST be
	// set so the issuer observed by the policy matches the issuer claim on
	// minted tokens. Otherwise policy decisions are made against a different
	// (or empty) issuer than what ends up in the token, which silently
	// splits the two code paths.
	if (options.grantPolicy) {
		const oauth = (config as { oauth?: { jwt?: { issuer?: unknown } } }).oauth;
		const issuer = oauth?.jwt?.issuer;
		if (typeof issuer !== "string" || issuer.length === 0) {
			throw new Error(
				"createApp: config.oauth.jwt.issuer must be set when grantPolicy is configured (policy evaluations and minted tokens must share a single trusted issuer)",
			);
		}
	}

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
		mfaProviderFactory: options.mfaProviderFactory,
		mfaCoordinator: options.mfaCoordinator,
		mfaTransactionStore: options.mfaTransactionStore,
		auditSink: options.auditSink,
		rateLimiter: options.rateLimiter,
		refreshTokenStore: options.refreshTokenStore,
		grantPolicy: options.grantPolicy,
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
