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
	memoryAccessTokenDenylistModule,
	memoryRateLimiterModule,
} from "@o3co/auth-provider-core";
import { googleFederationModule } from "@o3co/auth-provider-federation-google";
import {
	oauthAuthorizationModule,
	oauthModule,
	oauthSessionModule,
} from "@o3co/auth-provider-oauth";
import {
	redisAccessTokenDenylistModule,
	redisCodeRepositoryModule,
	redisFederationTokenStoreModuleFor,
	redisRateLimiterModule,
	redisRefreshTokenFamilyStoreModule,
	redisSessionStoresModule,
} from "@o3co/auth-provider-redis";
import { sessionModule, sessionStoreModuleFor } from "@o3co/auth-provider-session";
import {
	auditSinkModule,
	googleFederationConfigModule,
	inMemoryCodeRepositoryModule,
	inMemoryFederationTokenStoreModule,
	inMemorySessionStoresModule,
	keyStoreModule,
	repositoriesModule,
	standaloneRedisClientsModule,
} from "./modules.mjs";

/**
 * Overrides for the composition. All but `environment` are test-only: they let
 * the smoke test substitute in-memory implementations of the file-system-backed
 * modules, and production callers should not pass them — the defaults match the
 * standalone scaffold.
 */
export interface BuildModulesOverrides {
	/**
	 * #473: the name this deployment selected its configuration by —
	 * `CONFIG_ENV || NODE_ENV`, computed once in `app.mts` and passed here so
	 * the Redis federation-token store's `allow-plaintext` guard reads the
	 * environment the config actually came from, not `NODE_ENV` alone. Omitted,
	 * the guard falls back to `NODE_ENV` (and `deployment.mode`, which it reads
	 * off the config either way).
	 */
	readonly environment?: string;
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
	/**
	 * #287: override the module filling the `auditSink` slot. Tests substitute
	 * a sink they can assert on; the default writes the audit trail to stdout
	 * and is what a deployment gets.
	 *
	 * The override REPLACES the default — it does not add a second provider,
	 * which would be a boot-time slot collision. There is intentionally no way
	 * to pass "no audit sink": #304's sink policy is that the trail is always
	 * wired, and a composition that genuinely wants events discarded says so by
	 * providing a sink that discards them.
	 */
	readonly auditSinkModule?: Module;
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
	// #277: the RFC 7009 access-token denylist. Unlike the switches above there
	// is no "no denylist" branch — `oauthModule` reads the `accessTokenDenylist`
	// slot because it mounts `/oauth/revoke`, and core's boot validator refuses
	// a composition that reads the slot with nothing filling it, since the
	// endpoint would answer 200 while the token kept working. The switch here is
	// only over WHICH denylist.
	const accessTokenDenylistAdapter = config.accessTokenDenylist?.adapter ?? "memory";
	// #456: adapter switch for the federation token store. `"memory"` by
	// default, the template's local-dev shape; `"redis"` mounts
	// `redisFederationTokenStoreModule` off the shared socket — what the README
	// promised and what the previous factory-based module never delivered: it
	// built the Redis store without a client and failed at boot.
	const federationTokenStoreAdapter = config.federationTokenStore?.type ?? "memory";

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
		codeRepositoryAdapter === "redis" ||
		accessTokenDenylistAdapter === "redis" ||
		federationTokenStoreAdapter === "redis";

	// The four user-session stores switch on `userSessionStores.adapter`; the
	// federation-token store is always wired and switches on its own key
	// below (#456). Pre-Wave-5d the redis branch dropped the
	// federation-token-store provider entirely (Copilot review on PR #121);
	// splitting `storesModule` fixed that boot failure.
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

	// #277: mutually-exclusive denylist pair, same shape as the three switches
	// above. The memory branch is a dev convenience and nothing more: it forks
	// per replica, so `deployment.mode = "multi"` refuses it by name (see core's
	// replica-safety guard). The template's own application.conf ships `"redis"`.
	const accessTokenDenylistModules: Module[] =
		accessTokenDenylistAdapter === "redis"
			? [redisAccessTokenDenylistModule]
			: [memoryAccessTokenDenylistModule];

	// #455 / #456: mutually-exclusive federation-token-store pair, the same
	// shape as the session stores. One module per adapter, so the memory one
	// can declare `replicaSafety` on its manifest and the Redis one can
	// `require` its client slot. The previous single module chose the adapter
	// at runtime under one name — the replica guard could not tell the two
	// apart, and the Redis branch had no client to hand the builder.
	//
	// #473: the Redis module is built for this composition root so its
	// plaintext guard knows which environment selected the config; it reads
	// `deployment.mode` off the config itself.
	const federationTokenStoreModules: Module[] =
		federationTokenStoreAdapter === "redis"
			? [redisFederationTokenStoreModuleFor({ environment: overrides.environment })]
			: [inMemoryFederationTokenStoreModule];

	return [
		// D-5: sessionStoreModule wires the express-session middleware into the
		// boot-planner-managed lifecycle. **Mount order is enforced by this
		// list position (declarationIndex tie-breaking)** — the module
		// intentionally has no `before`/`after` clause, so it MUST be listed
		// ahead of every session-consuming module here. Do not reorder.
		//
		// #474: built from `config` rather than the static manifest, so that
		// `session.storage.type = "memory"` declares itself replica-unsafe and
		// `deployment.mode = "multi"` refuses it by name like the other stores.
		sessionStoreModuleFor(config),
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
		// #287: the audit sink, always wired. Unlike every switch above there is
		// no "off" branch — the routes' security events (`token.issued.failure`,
		// `authorize.rejected`, `rate_limit.unavailable`, …) went nowhere in the
		// shipped artifact because the slot was empty and `emitAuditEvent`
		// no-ops when it is. Which sink is a config question
		// (`audit.sink.type`); whether there is one is not.
		overrides.auditSinkModule ?? auditSinkModule,
		// Shared ioredis clients — only when at least one consumer adapter
		// actually needs Redis. Memory-only deployments skip this so they
		// don't open an unused socket.
		...(usingRedisAnywhere ? [standaloneRedisClientsModule] : []),
		// Federation-token store: redis (multi-replica) or memory (dev). Always
		// wired, independent of the `userSessionStores.adapter` switch — it was
		// bundled into `storesModule` pre-Wave-5d, and the redis session-stores
		// branch dropped the provider.
		...federationTokenStoreModules,
		// User-session-store family: redis (multi-replica) or memory (dev).
		...sessionStoresModules,
		// OAuth-endpoint rate limiter: redis (shared counters) or memory.
		...rateLimiterModules,
		// OAuth code repository: redis (multi-replica) or memory (single-instance).
		...codeRepositoryModules,
		// RFC 7009 access-token denylist: redis (shared revocations) or memory
		// (single-instance dev). Always wired — see the switch above.
		...accessTokenDenylistModules,
		// RT family store: redis by default (closes OR-1); override path
		// swaps to `[memoryRefreshTokenFamilyStoreModule]` for unit tests.
		...refreshTokenFamilyModules,
		defaultRefreshTokenFamilyRotationModule,
		defaultRefreshTokenFamilyRevocationModule,
	];
}
