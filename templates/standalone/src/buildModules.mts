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
	defaultRefreshTokenFamilyRevocationModule,
	defaultRefreshTokenFamilyRotationModule,
	jwksModule,
	type Module,
	memoryRateLimiterModule,
} from "@o3co/auth-provider-core";
import { googleFederationModule } from "@o3co/auth-provider-federation-google";
import {
	oauthAuthorizationModule,
	oauthModule,
	oauthSessionModule,
} from "@o3co/auth-provider-oauth";
import {
	redisCodeRepositoryModule,
	redisRateLimiterModule,
	redisRefreshTokenFamilyStoreModule,
	redisSessionStoresModule,
} from "@o3co/auth-provider-redis";
import { sessionModule, sessionStoreModule } from "@o3co/auth-provider-session";
import {
	federationTokenStoreModule,
	googleFederationConfigModule,
	inMemoryCodeRepositoryModule,
	inMemorySessionStoresModule,
	keyStoreModule,
	repositoriesModule,
	standaloneRedisClientsModule,
} from "./modules.mjs";

/**
 * Test-only overrides allowing the smoke test to substitute in-memory
 * implementations of the file-system-backed modules. Production callers
 * should not pass overrides; the defaults match the standalone scaffold.
 */
export interface BuildModulesOverrides {
	readonly keyStoreModule?: Module;
	readonly repositoriesModule?: Module;
	readonly storesModule?: Module;
	/**
	 * D-2 v2 / Wave 5d: override the RT family store module + (when adapter
	 * is `"redis"`) the bundled redis-clients + redis-store pair. Default
	 * production manifest is `[standaloneRedisClientsModule, redisRefreshTokenFamilyStoreModule]`
	 * (single shared ioredis socket per replica via the F4 PR2 unification).
	 *
	 * Smoke tests / unit tests that don't want to open an ioredis connection
	 * pass `[memoryRefreshTokenFamilyStoreModule]` here. The override REPLACES
	 * the entire group — when the override is provided, `standaloneRedisClientsModule`
	 * is dropped from the manifest unless the override list includes it.
	 */
	readonly refreshTokenFamilyModules?: readonly Module[];
}

/**
 * Compose the standalone v0.5.0 module list from `config`. Splitting this
 * out of `app.mts` keeps the composition root testable: a smoke test can
 * verify that disabling a federation removes its module pair from the
 * manifest without spinning up a full HTTP server.
 *
 * Federation gating: `googleFederationModule` requires `googleFederationConfig`,
 * which `googleFederationConfigModule` produces by reading
 * `config.federations.google`. When google is disabled (or the section is
 * absent), the config-bridge module's provider throws — so the entire pair
 * MUST be conditionally included at composition time, not gated inside the
 * provider.
 */
export function buildModules(config: AppConfig, overrides: BuildModulesOverrides = {}): Module[] {
	const googleEnabled =
		(config.federations?.google as { enabled?: boolean } | undefined)?.enabled === true;

	// Wave 5d (IH-14 + OR-M1 + OR-4) + OR-9: adapter-driven branching for
	// the OAuth-endpoint rate limiter, the user-session-store family, AND
	// the OAuth code repository. The RT family store always uses Redis in
	// the production manifest (D-2 v2 / OR-1) unless
	// `overrides.refreshTokenFamilyModules` swaps it out. When ANY consumer
	// adapter is `"redis"` (or the RT family override includes a
	// Redis-backed store module), the shared `standaloneRedisClientsModule`
	// is added once and provides every per-purpose ComponentMap slot from a
	// single ioredis socket per replica. Memory-only deployments skip it.
	const rateLimiterAdapter = config.rateLimiter?.adapter ?? "memory";
	const userSessionStoresAdapter = config.userSessionStores?.adapter ?? "memory";

	// OR-9: effective code-repo adapter. `oauth.code.adapter` is the
	// authoritative switch; the legacy `repositories.code.type = "redis"`
	// path is honored with a deprecation warn so existing operators
	// relying on `CLIENT_CODE_TYPE=redis` env-var overrides keep working
	// until they migrate. See CHANGELOG for the removal version.
	const oauthCodeAdapter = config.oauth?.code?.adapter;
	const legacyCodeType = (config.repositories?.code as { type?: string } | undefined)?.type;
	let codeRepositoryAdapter: "memory" | "redis";
	if (oauthCodeAdapter !== undefined) {
		codeRepositoryAdapter = oauthCodeAdapter;
	} else if (legacyCodeType === "redis") {
		console.warn(
			'[buildModules] `repositories.code.type = "redis"` is deprecated; use ' +
				'`oauth.code.adapter = "redis"` instead — see CHANGELOG for the removal version.',
		);
		codeRepositoryAdapter = "redis";
	} else {
		codeRepositoryAdapter = "memory";
	}

	const refreshTokenFamilyModules: readonly Module[] = overrides.refreshTokenFamilyModules ?? [
		redisRefreshTokenFamilyStoreModule,
	];
	// Detect whether the RT-family override (if any) keeps the Redis-backed
	// store. Default (no override) uses Redis. An override that includes the
	// Redis store module without also wiring `standaloneRedisClientsModule`
	// would otherwise boot-fail on the missing `refreshTokenFamilyClient`
	// component (Copilot review on PR #121).
	const refreshTokenFamilyUsesRedis = refreshTokenFamilyModules.some(
		(m) => m.name === "redis-refresh-token-family-store",
	);
	const usingRedisAnywhere =
		refreshTokenFamilyUsesRedis ||
		rateLimiterAdapter === "redis" ||
		userSessionStoresAdapter === "redis" ||
		codeRepositoryAdapter === "redis";

	// Federation-token store is always wired; only the 4 user-session
	// stores switch on the adapter. Pre-Wave-5d the redis branch dropped
	// the federation-token-store provider entirely (Copilot review on
	// PR #121); splitting `storesModule` fixes that boot failure.
	const sessionStoresModules: Module[] =
		userSessionStoresAdapter === "redis"
			? [redisSessionStoresModule]
			: overrides.storesModule
				? [overrides.storesModule]
				: [inMemorySessionStoresModule];

	const rateLimiterModules: Module[] =
		rateLimiterAdapter === "redis" ? [redisRateLimiterModule] : [memoryRateLimiterModule];

	// OR-9: code-repository module — mutually exclusive memory/redis pair.
	// Same pattern as sessionStoresModules + rateLimiterModules. The two
	// modules provide the same `codeRepository` slot; including both would
	// be a boot-time slot collision.
	const codeRepositoryModules: Module[] =
		codeRepositoryAdapter === "redis"
			? [redisCodeRepositoryModule]
			: [inMemoryCodeRepositoryModule];

	return [
		// D-5: sessionStoreModule wires the express-session middleware into the
		// boot-planner-managed lifecycle. **Mount order is enforced by this
		// list position (declarationIndex tie-breaking)** — the module
		// intentionally has no `before`/`after` clause, so it MUST be listed
		// ahead of every session-consuming module here. Do not reorder.
		sessionStoreModule,
		oauthModule({ config }),
		oauthSessionModule({ config }),
		oauthAuthorizationModule({ config }),
		// JWKS publishing — always wired (depends only on config + keyStore).
		// Contributed by core's `jwksModule`, NOT oauthModule: a provider that
		// signs tokens must publish its verification keys regardless of OIDC
		// issuer config. Co-installed with oauthModule so the discovery
		// `jwks_uri` (advertised by oauthModule when an issuer is set) always
		// resolves to this mounted route.
		jwksModule,
		sessionModule,
		...(googleEnabled ? [googleFederationModule, googleFederationConfigModule] : []),
		overrides.keyStoreModule ?? keyStoreModule,
		overrides.repositoriesModule ?? repositoriesModule,
		// Shared ioredis clients — only when at least one consumer adapter
		// actually needs Redis. Memory-only deployments skip this so they
		// don't open an unused socket.
		...(usingRedisAnywhere ? [standaloneRedisClientsModule] : []),
		// Federation-token store — always wired; independent of the
		// `userSessionStores.adapter` switch. Was bundled into `storesModule`
		// pre-Wave-5d; split so the redis session-stores branch doesn't
		// drop the provider.
		federationTokenStoreModule,
		// User-session-store family: redis (multi-replica) or memory (dev).
		...sessionStoresModules,
		// OAuth-endpoint rate limiter: redis (shared counters) or memory.
		...rateLimiterModules,
		// OAuth code repository: redis (multi-replica) or memory (single-instance).
		...codeRepositoryModules,
		// RT family store: redis by default (closes OR-1); override path
		// swaps to `[memoryRefreshTokenFamilyStoreModule]` for unit tests.
		...refreshTokenFamilyModules,
		defaultRefreshTokenFamilyRotationModule,
		defaultRefreshTokenFamilyRevocationModule,
	];
}
