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
import type { FederationTokenStoreBase } from "./federation-tokens/types.mjs";
import { GrantRegistry } from "./grants/registry.mjs";
import type { KeyStore } from "./keys/KeyStore.mjs";
import type { MfaCoordinator, MfaProviderFactory, MfaTransactionStore } from "./mfa/types.mjs";
import type { LegacyModule as Module, ModuleContext, PathResolver } from "./modules/types.mjs";
import type { GrantPolicyHookBase } from "./policy/types.mjs";
import type { RateLimiterBase } from "./ratelimit/types.mjs";
import type { RefreshTokenStoreBase } from "./refresh/types.mjs";
import * as healthcheck from "./routes/Healthcheck.mjs";
import * as jwks from "./routes/Jwks.mjs";
import type {
	SessionFamilyIndex,
	SessionFederationIndex,
	SessionRPRegistry,
	UserSessionStore,
} from "./user-sessions/types.mjs";

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
	userSessionStore?: UserSessionStore;
	sessionRPRegistry?: SessionRPRegistry;
	sessionFamilyIndex?: SessionFamilyIndex;
	sessionFederationIndex?: SessionFederationIndex;
	federationTokenStore?: FederationTokenStoreBase;
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

	// Spec Section 10.1 — federations configured means stores are required.
	// This runs BEFORE zod parsing, so `enabled` may still be a string from
	// env-var overrides (HOCON substitutions emit `"true"`/`"1"`). We MUST
	// accept exactly the strings that Plan #3's `coerceBooleanFromEnv`
	// zod-preprocess coerces to true, so this pre-parse check neither
	// (a) lets a schema-enabled federation slip through unchecked nor
	// (b) rejects a config that zod would later reject anyway (false
	// positive, mask the real schema error).
	//
	// Matches schema behavior: only `"true"` and `"1"` coerce to true.
	// Arbitrary strings like "yes"/"on" are rejected by the schema, so
	// treating them as truthy here would fire the stores-missing error
	// before the real validation message.
	const isEnabledTruthy = (v: unknown): boolean => {
		if (v === true) return true;
		if (typeof v !== "string") return false;
		const normalized = v.trim().toLowerCase();
		return normalized === "true" || normalized === "1";
	};
	const federationsCfg = (config as { federations?: Record<string, { enabled?: unknown }> })
		.federations;
	const federationsConfigured =
		typeof federationsCfg === "object" &&
		federationsCfg !== null &&
		Object.values(federationsCfg).some((f) => f != null && isEnabledTruthy(f.enabled));

	if (federationsConfigured && !options.federationTokenStore) {
		throw new Error(
			"createApp: federations are configured but federationTokenStore was not provided. " +
				"Register a FederationTokenStore adapter in AppOptions.",
		);
	}
	if (federationsConfigured && !options.userSessionStore) {
		throw new Error(
			"createApp: federations are configured but userSessionStore was not provided. " +
				"Register a UserSessionStore adapter in AppOptions.",
		);
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

	// OIDC discovery is mounted by the oauth module (when the OAuth endpoints
	// it advertises actually exist). See packages/oauth/src/module.mts.

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
		userSessionStore: options.userSessionStore,
		sessionRPRegistry: options.sessionRPRegistry,
		sessionFamilyIndex: options.sessionFamilyIndex,
		sessionFederationIndex: options.sessionFederationIndex,
		federationTokenStore: options.federationTokenStore,
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
