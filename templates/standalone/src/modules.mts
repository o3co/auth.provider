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
	consoleLogger,
	createAuditSinkFactory,
	createFederationTokenStoreFactory,
	createInMemorySessionFamilyIndex,
	createInMemorySessionFederationIndex,
	createInMemorySessionRPRegistry,
	createInMemoryUserSessionStore,
	createKeyStoreFactory,
	createRepositoryFactories,
	defineModule,
	type LifecycleRegistrar,
	type Logger,
	type Module,
	type ReadinessRegistrar,
	registerBuiltinAuditSinks,
	registerBuiltinFederationTokenStores,
	registerBuiltinKeyStores,
} from "@o3co/auth-provider-core";
import type { GoogleProviderConfig } from "@o3co/auth-provider-federation-google";
import { registerBuiltinAdapters } from "@o3co/auth-provider-foundation";
import { redisFederationTokenStoreBuilder } from "@o3co/auth-provider-redis";
import { makeIoredisClients } from "@o3co/auth-provider-redis/ioredis";
import { extractFederationSection } from "@o3co/auth-provider-session";
// Named import is required here, not default. ioredis is CJS and its entry
// does `module.exports = Redis` with the class re-exported as both `default`
// and `Redis`; under `module: "nodenext"` with esModuleInterop the default
// import therefore resolves to the module-exports namespace object rather
// than the class, and `new Redis(...)` raises TS2351 "not constructable".
// Still true on ioredis 6 — verified against 6.0.0, not inherited from the
// ioredis 5 era this note was first written in.
// The 11 default-import sites elsewhere in the repo all live under
// `packages/redis/__tests__/` which `packages/redis/tsconfig.json`
// explicitly excludes from strict tsc build (vitest's vue-tsc is more
// permissive about CJS interop). Standalone production source is built
// with strict nodenext, so the named import is the right shape here.
import { Redis } from "ioredis";
import { createAuditLogger, createLoggerAuditSink } from "./logger.mjs";

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
 * Audit-sink module — fills the `auditSink` slot every route that emits a
 * security event reads (#287).
 *
 * The slot is `optional` on `oauthModule`, `sessionModule` and `webauthnModule`,
 * and `emitAuditEvent` is a no-op when it is empty. That combination is why the
 * gap was invisible: the scaffold wired no sink, so `token.issued.failure`,
 * `authorize.rejected` / `authorize.granted`, `logout.cascade_failed` and the
 * shared rate-limit guard's `rate_limit.unavailable` were all discarded by the
 * deployable artifact, with nothing failing and nothing warning. This module is
 * always in the manifest for that reason — there is no "no audit sink" branch,
 * the way there is a memory/redis branch for the state stores.
 *
 * Two sink kinds are registered:
 *
 * - `"logger"` (the template's default) — one NDJSON line per event on stdout,
 *   in the same pino envelope as every other line this template emits, on a
 *   stream named `audit` whose level is fixed. See `createAuditLogger`.
 * - `"console"` — core's built-in, from `registerBuiltinAuditSinks`: the bare
 *   event as one JSON object per line on stdout, with no log envelope. For a
 *   pipeline that wants the event and nothing else.
 *
 * A deployment with a real sink (SIEM, log pipeline, message bus) registers its
 * builder here and names it in `audit.sink.type`; its options ride along in the
 * same config block (`flattenAdapterConfig` unwraps `sink { type = "x", x { … } }`).
 *
 * One thing to know before writing such a builder: `createAuditSinkFactory()`
 * takes no `BuilderContext`, so a sink builder receives `{}` and the
 * `ctx.lifecycle?.register(…)` / `ctx.readiness?.register(…)` calls that
 * CONTRIBUTING.md requires of a builder opening a connection are silent no-ops
 * here. A sink holding a socket must own its cleanup another way until that
 * factory takes a context.
 *
 * There is deliberately no `"none"`. An unknown type — including the `"none"`
 * an operator might reasonably guess at — fails boot naming the sinks that
 * exist, rather than producing a deployment with no audit trail (#304).
 */
export const auditSinkModule: Module = defineModule({
	name: "standalone:audit-sink",
	requires: ["config"] as const,
	provides: {
		auditSink: async ({ config }) => {
			const factory = createAuditSinkFactory();
			registerBuiltinAuditSinks(factory);
			factory.register("logger", () => createLoggerAuditSink(createAuditLogger()));
			const slice = (config as AppConfig).audit?.sink;
			// Absence lands on the default sink rather than on `undefined`: a
			// config that says nothing about auditing is not a config asking for
			// the events to be dropped. The literal default lives in HOCON
			// (`reference.conf` / `application.conf`); this is the floor under a
			// hand-built config that never met either.
			return factory.create(
				slice
					? flattenAdapterConfig(slice as { type: string } & Record<string, unknown>)
					: { type: "logger" },
			);
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
 * per replica, wraps it via `makeIoredisClients()` (returns 11 typed
 * per-purpose clients), and exposes the slots consumed by the standalone's
 * Redis-backed adapters (refresh-token-family + 4 user-session stores +
 * rate limiter + code repository + access-token denylist).
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
	optional: ["lifecycleRegistrar", "readinessRegistrar", "logger"] as const,
	provides: {
		refreshTokenFamilyClient: async ({
			config,
			lifecycleRegistrar,
			readinessRegistrar,
			logger,
		}) => {
			return getOrCreateClients(config as AppConfig, lifecycleRegistrar, readinessRegistrar, logger)
				.refreshTokenFamilyClient;
		},
		userSessionStoreClient: async ({ config, lifecycleRegistrar, readinessRegistrar, logger }) => {
			return getOrCreateClients(config as AppConfig, lifecycleRegistrar, readinessRegistrar, logger)
				.userSessionStoreClient;
		},
		sessionRPRegistryClient: async ({ config, lifecycleRegistrar, readinessRegistrar, logger }) => {
			return getOrCreateClients(config as AppConfig, lifecycleRegistrar, readinessRegistrar, logger)
				.sessionRPRegistryClient;
		},
		sessionFamilyIndexClient: async ({
			config,
			lifecycleRegistrar,
			readinessRegistrar,
			logger,
		}) => {
			return getOrCreateClients(config as AppConfig, lifecycleRegistrar, readinessRegistrar, logger)
				.sessionFamilyIndexClient;
		},
		sessionFederationIndexClient: async ({
			config,
			lifecycleRegistrar,
			readinessRegistrar,
			logger,
		}) => {
			return getOrCreateClients(config as AppConfig, lifecycleRegistrar, readinessRegistrar, logger)
				.sessionFederationIndexClient;
		},
		rateLimiterClient: async ({ config, lifecycleRegistrar, readinessRegistrar, logger }) => {
			return getOrCreateClients(config as AppConfig, lifecycleRegistrar, readinessRegistrar, logger)
				.rateLimiterClient;
		},
		// OR-9: code-repository client wired off the same shared ioredis
		// socket. `redisCodeRepositoryModule` consumes this slot when
		// `oauth.code.adapter = "redis"`. Codes are short-TTL (60-600s)
		// high-volume — sharing the connection avoids opening a separate
		// socket while the per-purpose typed wrapper keeps the Redis
		// command surface consumed by RedisCodeRepository explicit.
		codeRepositoryClient: async ({ config, lifecycleRegistrar, readinessRegistrar, logger }) => {
			return getOrCreateClients(config as AppConfig, lifecycleRegistrar, readinessRegistrar, logger)
				.codeRepositoryClient;
		},
		// #277: access-token denylist client, off the same shared socket. A
		// denylist is only worth having if every replica reads the same one —
		// that is the entire reason `redisAccessTokenDenylistModule` exists — so
		// it belongs on the connection the rest of the shared state already uses
		// rather than opening a second one.
		accessTokenDenylistClient: async ({
			config,
			lifecycleRegistrar,
			readinessRegistrar,
			logger,
		}) => {
			return getOrCreateClients(config as AppConfig, lifecycleRegistrar, readinessRegistrar, logger)
				.accessTokenDenylistClient;
		},
	},
});

/**
 * Failure-timing options for the one shared ioredis socket (#286).
 *
 * On the driver's defaults this connection had no `commandTimeout` at all, so
 * a partition did not produce errors — it produced *waiting*. Every `/token`
 * request that touched Redis parked in the offline queue while the socket
 * reconnected, and because nothing threw, the `rateLimit.failMode = "closed"`
 * policy (`createRateLimitGuard`, OR-5) never engaged: it only fires when
 * `limiter.check()` rejects. The load the policy exists to shed kept arriving
 * and kept accumulating, and memory and sockets grew until ioredis's 20th
 * reconnect attempt finally flushed the queue — tens of seconds later.
 *
 * The values below are chosen against the actual command surface of this
 * socket, which is entirely O(1) primitives and small paged scans
 * (`SET`/`GET`/`DEL`/`EXISTS`/`PTTL`/`INCR`/`EVAL`/`HSCAN`/`SSCAN`/`ZADD`/…).
 * There is no blocking command here, so no legitimate command has any reason
 * to take a meaningful fraction of a second.
 *
 * - `commandTimeout: 1000` — the hard ceiling on any single command. ioredis
 *   arms this timer in `sendCommand`, *before* the writability check, so it
 *   bounds a command that went into the offline queue exactly as it bounds one
 *   already on the wire. That is what makes the queued case fail rather than
 *   hang, and it is also the only guard that survives the nastiest partition
 *   shape: a zombie TCP connection where no `close` event ever fires, so the
 *   reconnect path described next is never entered at all.
 * - `maxRetriesPerRequest: 3` — on the fourth reconnect attempt (roughly
 *   0.4–1 s in on ioredis 6's jittered exponential backoff) the whole queue is
 *   failed in one go with `MaxRetriesPerRequestError`, rather than on the
 *   twentieth as the default has it. `commandTimeout` alone bounds each command's
 *   *latency*, but the queue would still grow to (request rate × 1 s) entries
 *   for as long as the outage lasted; this bounds its *depth*. Three rather
 *   than one so an ordinary sub-second reconnect blip is ridden out silently.
 * - `connectTimeout: 5000` — halves the driver's 10 s default. A dropped SYN
 *   (a partition that black-holes packets rather than refusing them) is the
 *   only case that reaches this ceiling; a real connect on any deployment
 *   topology this template targets completes in well under a second.
 * - `enableOfflineQueue: true` — the driver default, declared explicitly
 *   because it is a decision, not an inherited value. See below.
 * - `lazyConnect: false` — also the driver default (still, on ioredis 6),
 *   declared so the boot-time-connect contract survives a future flip.
 *
 * **Why the offline queue stays on.** Turning it off is the sharper answer for
 * the rate limiter specifically: a command issued while the socket is down
 * rejects immediately instead of after `commandTimeout`, so the fail-closed
 * policy sheds load at the first request rather than one second per request
 * later. But `enableOfflineQueue` is a per-**connection** option, and this
 * template runs every purpose off one socket — refresh-token families, the
 * four user-session stores, the authorization-code repository, the
 * access-token denylist and the rate limiter all come out of a single
 * `makeIoredisClients(io)` call (pinned by "one connection in, one connection
 * used" in `packages/redis/__tests__/ioredis.test.mts`). There is no way to
 * express "off here, on there" without opening a second socket, which is the
 * connection-pool pressure the shared-socket design was built to avoid.
 *
 * So the choice is one setting for all eleven purposes, and `false` is the
 * wrong one to pick for all eleven: it converts every reconnect — including
 * the sub-second blip of a routine managed-Redis failover, during which
 * ioredis would have recovered transparently — into hard errors on session
 * lookup, code redemption and refresh rotation. A failed refresh rotation is
 * not a retryable blip to the end user; it is a re-login.
 *
 * `true` costs the rate limiter up to `commandTimeout` of delay before it
 * starts shedding, and that is the honest trade. It is affordable precisely
 * because `commandTimeout` exists: the pile-up is now bounded by
 * (request rate × 1 s) and self-draining, rather than unbounded and growing.
 * A deployment that wants the sharper behavior gives the rate limiter its own
 * connection in its own composition root — the per-purpose client interfaces
 * exist for exactly that, and it is a deliberate second socket rather than a
 * silent global.
 */
const SHARED_REDIS_TIMEOUTS = {
	commandTimeout: 1_000,
	connectTimeout: 5_000,
	maxRetriesPerRequest: 3,
	enableOfflineQueue: true,
	lazyConnect: false,
} as const;

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
	injectedLogger?: Logger,
): ReturnType<typeof makeIoredisClients> {
	const logger = injectedLogger ?? consoleLogger;
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

	const io = new Redis(cfg.url, { password, ...SHARED_REDIS_TIMEOUTS });

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
 * Reads an optional string field off a federation slice.
 *
 * A field the operator did not set stays absent rather than becoming
 * `undefined`, so `"sessionDomain" in config` still distinguishes the two. A
 * field that is present but not a string throws: HOCON hands through whatever
 * shape the file holds, and silently ignoring `sessionDomain = 42` would leave
 * the redirect policy running with one fewer constraint than the operator
 * wrote down.
 */
function optionalString(
	slice: Record<string, unknown>,
	field: string,
): Record<string, string> | Record<string, never> {
	const value = slice[field];
	if (value === undefined || value === null) return {};
	if (typeof value !== "string") {
		throw new Error(`federations.google.${field} must be a string when present`);
	}
	return { [field]: value };
}

/**
 * Google federation config bridge — supplies the typed `googleFederationConfig`
 * ComponentMap slot from the `config.federations.google` slice.
 *
 * Per `@o3co/auth-provider-federation-google` README. Per-federation modules
 * (Phase 7 A5) consume this slot; the bridge is the standalone composition
 * root's responsibility because the slot's content is consumer-specific.
 *
 * #278: this used to return `{ clientId, clientSecret, callbackURL }` and stop
 * there, dropping `redirectAllowlist` / `sessionDomain` / `authCallbackUrl` /
 * `clientUrl` on the floor. Nothing complained — `googleFederationModule` hands
 * this same object to `createFederationRedirectPolicy`, so the redirect policy
 * was built from a config with none of the fields it reads, and a deployment
 * that had configured them ran as though it had not. The generated app is the
 * shape most operators start from, so the safe path has to be the one that
 * works by filling in the config file.
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

			// The allowlist is checked for shape here and for content by
			// `createFederationRedirectPolicy`, which owns the URL rules. This
			// only has to establish that HOCON produced a list of strings —
			// `redirectAllowlist = "https://…"` (a bare string, the natural typo)
			// would otherwise reach the policy as a config it cannot read.
			const rawAllowlist = slice.redirectAllowlist;
			let redirectAllowlist: Record<string, readonly string[]> | Record<string, never> = {};
			if (rawAllowlist !== undefined && rawAllowlist !== null) {
				if (!Array.isArray(rawAllowlist) || rawAllowlist.some((e) => typeof e !== "string")) {
					throw new Error(
						"federations.google.redirectAllowlist must be a list of URL strings, " +
							'e.g. ["https://app.example.com/welcome"]',
					);
				}
				redirectAllowlist = { redirectAllowlist: rawAllowlist as readonly string[] };
			}

			return {
				clientId,
				clientSecret,
				callbackURL,
				...redirectAllowlist,
				...optionalString(slice, "sessionDomain"),
				...optionalString(slice, "authCallbackUrl"),
				...optionalString(slice, "clientUrl"),
			};
		},
	},
});
