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
import path from "node:path";
import {
	type AppConfig,
	createFederationTokenStoreFactory,
	createInMemorySessionFamilyIndex,
	createInMemorySessionFederationIndex,
	createInMemorySessionRPRegistry,
	createInMemoryUserSessionStore,
	createKeyStoreFactory,
	createRepositoryFactories,
	defineModule,
	type LifecycleRegistrar,
	type Module,
	type ReadinessRegistrar,
	registerBuiltinFederationTokenStores,
	registerBuiltinKeyStores,
} from "@o3co/auth-provider-core";
import type { GoogleProviderConfig } from "@o3co/auth-provider-federation-google";
import { registerBuiltinAdapters } from "@o3co/auth-provider-foundation";
import { redisFederationTokenStoreBuilder } from "@o3co/auth-provider-redis";
import { makeIoredisClients } from "@o3co/auth-provider-redis/ioredis";
import { extractFederationSection } from "@o3co/auth-provider-session";
// Named import is required here, not default. Under `module: "nodenext"`
// with esModuleInterop, the default import resolves to the entire ioredis
// CJS module-exports namespace object (because ioredis 5.x ships
// `export = Redis`), so `new Redis(...)` raises TS2351 "not constructable".
// The 11 default-import sites elsewhere in the repo all live under
// `packages/redis/__tests__/` which `packages/redis/tsconfig.json`
// explicitly excludes from strict tsc build (vitest's vue-tsc is more
// permissive about CJS interop). Standalone production source is built
// with strict nodenext, so the named import is the right shape here.
import { Redis } from "ioredis";

import logger from "./logger.mjs";

/**
 * Helper: turn a v0.4.x { type, [type]: {...} } adapter-config slice into the
 * flat `{ type, ...rest }` shape consumed by AdapterFactory<T>.create().
 *
 * Composition-root concern; not a library export.
 */
function flattenAdapterConfig(
	section: ({ type: string } | { provider: string }) & Record<string, unknown>,
): { type: string } & Record<string, unknown> {
	const selector =
		(section as { type?: string; provider?: string }).type ??
		(section as { provider?: string }).provider;
	if (typeof selector !== "string") {
		throw new TypeError("flattenAdapterConfig: section requires 'type' or 'provider' string");
	}
	const sub = section[selector];
	const flattenedSub =
		typeof sub === "object" && sub !== null && !Array.isArray(sub)
			? (sub as Record<string, unknown>)
			: {};
	return { type: selector, ...flattenedSub };
}

/**
 * KeyStore module — provides the JWT signing KeyStore from config.
 *
 * Per A2-γ §4 worked example. Composition-root-local: the standalone template
 * uses the built-in local/jwks adapters; alternative deployments wire their
 * own KeyStore via a different module of the same shape.
 */
export const keyStoreModule: Module = defineModule({
	name: "standalone:key-store",
	requires: ["config"] as const,
	provides: {
		keyStore: async ({ config }) => {
			const factory = createKeyStoreFactory();
			registerBuiltinKeyStores(factory);
			return factory.create(flattenAdapterConfig((config as AppConfig).oauth.jwt.signingKey));
		},
	},
});

/**
 * Repositories module — provides client / user repositories from
 * `config.repositories.*` slices using the built-in adapter factories.
 *
 * Pre-OR-9 this module also provided `codeRepository` — split out into
 * `inMemoryCodeRepositoryModule` (memory branch) / `redisCodeRepositoryModule`
 * (redis branch, from `@o3co/auth-provider-redis`) so the
 * `oauth.code.adapter` switch can wire mutually-exclusive providers without
 * a slot collision. Same pattern as the Wave-5d userSessionStores split.
 */
export const repositoriesModule: Module = defineModule({
	name: "standalone:repositories",
	requires: ["config"] as const,
	// D-5 / OR-2 / IH-11: forward `lifecycleRegistrar` into the repository
	// factories so client/user adapters can register disposal callbacks
	// (e.g. file-watch closers). Without this, builders' `ctx.lifecycle?.register`
	// is a no-op and the leaks remain.
	optional: ["lifecycleRegistrar"] as const,
	provides: {
		clientRepository: async ({ config, lifecycleRegistrar }) => {
			const ctx = { lifecycle: lifecycleRegistrar };
			const { clientFactory, userFactory } = createRepositoryFactories(ctx);
			registerBuiltinAdapters({ userFactory });
			const slice = flattenAdapterConfig(
				(config as AppConfig).repositories.client as { type: string } & Record<string, unknown>,
			);
			if (typeof slice.path === "string") {
				slice.path = path.resolve(process.cwd(), slice.path);
			}
			return clientFactory.create(slice);
		},
		userRepository: async ({ config, lifecycleRegistrar }) => {
			const ctx = { lifecycle: lifecycleRegistrar };
			const { userFactory } = createRepositoryFactories(ctx);
			registerBuiltinAdapters({ userFactory });
			return userFactory.create(
				flattenAdapterConfig(
					(config as AppConfig).repositories.user as { type: string } & Record<string, unknown>,
				),
			);
		},
	},
});

/**
 * In-memory CodeRepository module — wired by `buildModules` only when
 * `oauth.code.adapter = "memory"`. The redis branch swaps in
 * `redisCodeRepositoryModule` from `@o3co/auth-provider-redis` (mutually
 * exclusive — both modules provide the same `codeRepository` slot).
 *
 * Per OR-9 (Wave 5d) split: pre-OR-9 the codeRepository slot was provided
 * inside `repositoriesModule` via the AdapterFactory pattern; that path
 * coupled the slot to `repositories.code.type` which is now superseded by
 * `oauth.code.adapter`.
 */
export const inMemoryCodeRepositoryModule: Module = defineModule({
	name: "standalone:in-memory-code-repository",
	requires: ["config"] as const,
	optional: ["lifecycleRegistrar"] as const,
	provides: {
		codeRepository: async ({ config, lifecycleRegistrar }) => {
			const ctx = { lifecycle: lifecycleRegistrar };
			const { codeFactory } = createRepositoryFactories(ctx);
			// `codeFactory.register("memory", ...)` is wired automatically by
			// `createRepositoryFactories` itself (see core/repositories/RepositoryFactory.mts).
			// `registerBuiltinAdapters` from `@o3co/auth-provider-foundation` only
			// registers the HTTP user adapter on `userFactory`; it does NOT touch
			// `codeFactory`, so calling it here would be misleading and unnecessary.
			//
			// The flattened slice MAY still have `type = "redis"` when only the
			// legacy `repositories.code.type` is set — `buildModules`' adapter
			// resolution already chose memory by the time we get here, so
			// override the type explicitly to keep this module robust against
			// legacy HOCON shapes.
			const slice = flattenAdapterConfig(
				(config as AppConfig).repositories.code as { type: string } & Record<string, unknown>,
			);
			return codeFactory.create({ ...slice, type: "memory" });
		},
	},
});

/**
 * In-memory user-session stores module — provides the four-store
 * user-session split (userSessionStore, sessionRPRegistry,
 * sessionFamilyIndex, sessionFederationIndex). This module is wired by
 * `buildModules` only when `userSessionStores.adapter = "memory"`. The
 * Redis branch swaps in `redisSessionStoresModule` from
 * `@o3co/auth-provider-redis`.
 *
 * Pre-Wave-5d this module also provided `federationTokenStore` (now
 * extracted into a separate always-wired module so the redis session
 * branch doesn't drop the federation-token-store provider — Copilot
 * review on PR #121).
 */
export const inMemorySessionStoresModule: Module = defineModule({
	name: "standalone:in-memory-session-stores",
	provides: {
		userSessionStore: () => createInMemoryUserSessionStore(),
		sessionRPRegistry: () => createInMemorySessionRPRegistry(),
		sessionFamilyIndex: () => createInMemorySessionFamilyIndex(),
		sessionFederationIndex: () => createInMemorySessionFederationIndex(),
	},
});

/**
 * Federation token store module — always wired (independent of the
 * `userSessionStores.adapter` switch). Pre-Wave-5d this slot was bundled
 * into the larger `storesModule`; that meant the redis session-stores
 * branch dropped the federation-token-store provider entirely and boot
 * failed on the missing component (Copilot review on PR #121). Splitting
 * the slot out lets both adapters reuse it unchanged.
 */
export const federationTokenStoreModule: Module = defineModule({
	name: "standalone:federation-token-store",
	requires: ["config"] as const,
	provides: {
		federationTokenStore: async ({ config }) => {
			const factory = createFederationTokenStoreFactory();
			registerBuiltinFederationTokenStores(factory);
			factory.register("redis", redisFederationTokenStoreBuilder);
			const slice = (
				config as AppConfig & {
					federationTokenStore?: { type: string } & Record<string, unknown>;
				}
			).federationTokenStore;
			return factory.create(slice ? flattenAdapterConfig(slice) : { type: "memory" });
		},
	},
});

/**
 * @deprecated since Wave 5d (F4 PR2): split into `inMemorySessionStoresModule`
 * + `federationTokenStoreModule`. Re-exported for backward compatibility
 * with consumers that imported `storesModule` from this file. New code
 * should use the two split modules directly.
 */
export const storesModule: Module = defineModule({
	name: "standalone:stores",
	requires: ["config"] as const,
	provides: {
		...inMemorySessionStoresModule.provides,
		...federationTokenStoreModule.provides,
	},
});

/**
 * Shared ioredis clients module — opens ONE long-lived ioredis connection
 * per replica, wraps it via `makeIoredisClients()` (returns 9 typed
 * per-purpose clients), and exposes the slots consumed by the standalone's
 * Redis-backed adapters (refresh-token-family + 4 user-session stores +
 * rate limiter).
 *
 * Per F4 PR1 (D-2 v2) + Wave 5d unification: the previous design opened a
 * separate ioredis socket per Redis-backed module (3+ sockets per replica).
 * This module consolidates them — `makeIoredisClients(io)` was always
 * designed to derive multiple per-purpose typed clients from a single
 * connection; using one socket realises that intent and minimises
 * connection-pool pressure on the upstream Redis.
 *
 * Connection-config: reuses `refreshTokenFamilyStore.redis.{url, password}`
 * (declared in `fullSectionsSchema` by D-2 v2 §1). No new top-level config
 * key is introduced — the connection is shared so its config is too. Future
 * splits (per-store distinct Redis instances) are operator-side via custom
 * composition roots, not standalone configuration.
 *
 * Fails fast (throws) when the Redis URL is absent. The HOCON default in
 * `application.conf` covers single-instance / dev scenarios; an operator
 * who deliberately removes the section in production sees an explicit
 * error instead of a silent localhost fallback (the multi-replica failure
 * mode OR-1 was supposed to close).
 *
 * Lifecycle: registers `io.quit()` once with the boot-planner-pre-seeded
 * `lifecycleRegistrar` (D-5 ComponentMap slot) so `handle.dispose()` quits
 * the single connection cleanly.
 *
 * Conditional inclusion: `buildModules` only adds this module to the
 * manifest when at least one Redis-backed adapter is selected
 * (`userSessionStores.adapter = "redis"` OR `rateLimiter.adapter = "redis"`
 * — refresh-token-family is always Redis-backed in production). Adding the
 * module unconditionally would open an ioredis socket for memory-only
 * deployments.
 */
export const standaloneRedisClientsModule: Module = defineModule({
	name: "standalone:redis-clients",
	requires: ["config"] as const,
	optional: ["lifecycleRegistrar", "readinessRegistrar"] as const,
	provides: {
		refreshTokenFamilyClient: async ({ config, lifecycleRegistrar, readinessRegistrar }) => {
			return getOrCreateClients(config as AppConfig, lifecycleRegistrar, readinessRegistrar)
				.refreshTokenFamilyClient;
		},
		userSessionStoreClient: async ({ config, lifecycleRegistrar, readinessRegistrar }) => {
			return getOrCreateClients(config as AppConfig, lifecycleRegistrar, readinessRegistrar)
				.userSessionStoreClient;
		},
		sessionRPRegistryClient: async ({ config, lifecycleRegistrar, readinessRegistrar }) => {
			return getOrCreateClients(config as AppConfig, lifecycleRegistrar, readinessRegistrar)
				.sessionRPRegistryClient;
		},
		sessionFamilyIndexClient: async ({ config, lifecycleRegistrar, readinessRegistrar }) => {
			return getOrCreateClients(config as AppConfig, lifecycleRegistrar, readinessRegistrar)
				.sessionFamilyIndexClient;
		},
		sessionFederationIndexClient: async ({ config, lifecycleRegistrar, readinessRegistrar }) => {
			return getOrCreateClients(config as AppConfig, lifecycleRegistrar, readinessRegistrar)
				.sessionFederationIndexClient;
		},
		rateLimiterClient: async ({ config, lifecycleRegistrar, readinessRegistrar }) => {
			return getOrCreateClients(config as AppConfig, lifecycleRegistrar, readinessRegistrar)
				.rateLimiterClient;
		},
		// OR-9: code-repository client wired off the same shared ioredis
		// socket. `redisCodeRepositoryModule` consumes this slot when
		// `oauth.code.adapter = "redis"`. Codes are short-TTL (60-600s)
		// high-volume — sharing the connection avoids opening a separate
		// socket while the per-purpose typed wrapper keeps the Redis
		// command surface consumed by RedisCodeRepository explicit.
		codeRepositoryClient: async ({ config, lifecycleRegistrar, readinessRegistrar }) => {
			return getOrCreateClients(config as AppConfig, lifecycleRegistrar, readinessRegistrar)
				.codeRepositoryClient;
		},
	},
});

// Module-scoped cache so each `provides.*` factory invocation reuses the
// same `Redis` instance (and its `makeIoredisClients()` derivation) within
// a single createApp() invocation. The boot planner calls each `provides`
// in dependency order; without this, every consumed slot would create its
// own Redis socket, defeating the unification purpose.
//
// Cache key: the `lifecycleRegistrar` IDENTITY (which is per-boot — each
// `createApp()` invocation seeds a fresh registrar via the boot planner).
// Keying solely on `config` would incorrectly share connections across
// boots when the same config object is reused with a new registrar (and
// only the FIRST boot's registrar would receive disposal — Copilot review
// on PR #121). When `lifecycleRegistrar` is undefined (test scenarios
// that don't seed it), each call creates a fresh client; tests are
// isolated and don't need cross-slot sharing.
const clientsCache = new WeakMap<LifecycleRegistrar, ReturnType<typeof makeIoredisClients>>();
function getOrCreateClients(
	config: AppConfig,
	lifecycleRegistrar: LifecycleRegistrar | undefined,
	readinessRegistrar?: ReadinessRegistrar,
): ReturnType<typeof makeIoredisClients> {
	const cached = lifecycleRegistrar ? clientsCache.get(lifecycleRegistrar) : undefined;
	if (cached) return cached;

	const cfg = config.refreshTokenFamilyStore?.redis;
	if (typeof cfg?.url !== "string" || cfg.url.length === 0) {
		throw new Error(
			"standaloneRedisClientsModule: `refreshTokenFamilyStore.redis.url` is required when any " +
				"Redis-backed adapter is selected. Set REFRESH_TOKEN_FAMILY_STORE_REDIS_URL or " +
				"restore the `refreshTokenFamilyStore.redis` block in application.conf. Multi-replica " +
				"deployments require a shared Redis 7.2+ instance.",
		);
	}
	const password = typeof cfg.password === "string" ? cfg.password : undefined;

	// `lazyConnect: false` is the ioredis 5.x default; the explicit option
	// documents the boot-time-connect contract so a future ioredis version
	// flip does not silently change the failure mode.
	const io = new Redis(cfg.url, { password, lazyConnect: false });

	// Attach an error handler so unhandled "error" events do not crash the
	// process. Initial connection failures surface here; downstream adapter
	// operations then fail visibly.
	io.on("error", (err: unknown) => {
		logger.error({ err }, "standalone_redis_clients_error");
	});

	lifecycleRegistrar?.register(async () => {
		await io.quit();
	});

	// One probe for the one socket. Registering per consumed slot would report
	// the same connection six times; the cache above means this runs once per
	// boot, on the call that actually constructs the client.
	readinessRegistrar?.register({
		name: "redis",
		check: () => io.ping(),
	});

	// The wrapper opens its own connections for refresh rotation
	// (`refreshTokenFamilyClient.duplicate()`), which inherit no listeners from
	// `io`; passing the logger lets those report through the same channel.
	const clients = makeIoredisClients(io, { logger });
	if (lifecycleRegistrar) clientsCache.set(lifecycleRegistrar, clients);
	return clients;
}

/**
 * Google federation config bridge — supplies the typed `googleFederationConfig`
 * ComponentMap slot from the `config.federations.google` slice.
 *
 * Per `@o3co/auth-provider-federation-google` README. Per-federation modules
 * (Phase 7 A5) consume this slot; the bridge is the standalone composition
 * root's responsibility because the slot's content is consumer-specific.
 */
export const googleFederationConfigModule: Module = defineModule({
	name: "standalone:google-federation-config",
	requires: ["config"] as const,
	provides: {
		googleFederationConfig: ({ config }): GoogleProviderConfig => {
			const slice = extractFederationSection((config as AppConfig).federations, "google");
			if (!slice) {
				throw new Error(
					"federations.google must be enabled with credentials when googleFederationModule is in the manifest",
				);
			}
			const clientId = slice.clientId;
			const clientSecret = slice.clientSecret;
			const callbackURL = slice.callbackURL;
			if (
				typeof clientId !== "string" ||
				typeof clientSecret !== "string" ||
				typeof callbackURL !== "string"
			) {
				throw new Error(
					"federations.google requires clientId, clientSecret, callbackURL when enabled",
				);
			}
			return { clientId, clientSecret, callbackURL };
		},
	},
});
