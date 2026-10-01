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
	consoleLogger,
	createAuditSinkFactory,
	createFederationTokenStoreFactory,
	createInMemorySessionFamilyIndex,
	createInMemorySessionFederationIndex,
	createInMemorySessionRPRegistry,
	createInMemorySubjectRevocation,
	createInMemorySubjectSessionIndex,
	createInMemoryUserSessionStore,
	createKeyStoreFactory,
	createRepositoryFactories,
	defineModule,
	federationsOf,
	type LifecycleRegistrar,
	type Logger,
	loggableError,
	type Module,
	type ReadinessRegistrar,
	registerBuiltinAuditSinks,
	registerBuiltinFederationTokenStores,
	registerBuiltinKeyStores,
} from "@o3co/auth-provider-core";
import type { GoogleProviderConfig } from "@o3co/auth-provider-federation-google";
import { readOidcFederationConfigs } from "@o3co/auth-provider-federation-oidc";
import { registerBuiltinAdapters } from "@o3co/auth-provider-foundation";
import {
	makeIoredisClients,
	makeIoredisFederationGrantIntentStoreClient,
	makeIoredisFederationGrantStoreClient,
} from "@o3co/auth-provider-redis/ioredis";
import { extractFederationSection } from "@o3co/auth-provider-session";
// Named import, not default: ioredis is CJS (`module.exports = Redis`, the
// class re-exported as both `default` and `Redis`), so under `module:
// "nodenext"` with esModuleInterop the default import resolves to the
// module-exports namespace object and `new Redis(...)` raises TS2351 "not
// constructable". Verified against ioredis 6.0.0. The repo's default-import
// sites live under `packages/redis/__tests__/`, which the strict tsc build
// excludes.
import { Redis } from "ioredis";
import { createAuditLogger, createLoggerAuditSink } from "./logger.mjs";
import {
	type Adapters,
	auditSinkSectionSchema,
	httpSectionSchema,
	inMemoryCodeRepositorySectionSchema,
	keyStoreSectionSchema,
	loggingSectionSchema,
	redisClientsSectionSchema,
	repositoriesSectionSchemaFor,
} from "./sections.mjs";

/**
 * Turn a `{ type, [type]: {...} }` adapter-config slice into the flat
 * `{ type, ...rest }` shape `AdapterFactory<T>.create()` consumes.
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
 * The template's `config/reference.conf`, resolved from this file, which sits
 * one directory under the template's root in `src/` and in `dist/` alike.
 */
const TEMPLATE_REFERENCE_HREF: string = new URL("../config/reference.conf", import.meta.url).href;

/**
 * The template's `config/reference.conf`, which every module here that owns a
 * section declares. A new `URL` per call: a shared one could be changed in place.
 */
export function templateReference(): URL {
	return new URL(TEMPLATE_REFERENCE_HREF);
}

/**
 * Logging module: owns `logging {}`. It provides nothing: the logger is built
 * before boot from this section (`readLogging`) and handed in as a bootstrap
 * component, since the template logs while it chooses its modules.
 * `LOG_LEVEL` is renamed after the path, `LOGGING_LEVEL`.
 */
export const loggingModule = defineModule({
	name: "logging",
	section: {
		schema: loggingSectionSchema,
		reference: templateReference(),
		renamedVariables: { LOG_LEVEL: "logging.level" },
	},
});

/** What the host process reads of `http {}`, beside what the `httpSettings` slot carries. */
export interface HttpHostSettings {
	/** The port the server listens on; `0` lets the OS pick one. */
	readonly port: number;
	/** The per-probe deadline of `/readyz` and the metrics scrape, in milliseconds. */
	readonly readinessTimeoutMs: number;
}

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/** What the host process reads of `http {}`: provided by the `http` module. */
		readonly httpHostSettings?: HttpHostSettings;
	}
}

/**
 * HTTP module: owns `http {}`, its CORS list (`http.cors`) included, and
 * provides core's `httpSettings`, authoritative, and the host's
 * `httpHostSettings`, both eager: only `app.mts` reads the host's, and no
 * module requires it. The list moved from `cors`, and `CORS_ALLOWED_ORIGINS`
 * with it.
 */
export const httpModule = defineModule({
	name: "http",
	section: {
		schema: httpSectionSchema,
		reference: templateReference(),
		relocatedFrom: { cors: "cors" },
		renamedVariables: { CORS_ALLOWED_ORIGINS: "cors.allowedOrigins" },
	},
	provides: {
		httpSettings: ({ section }) =>
			Object.freeze({
				trustProxy: section.trustProxy,
				cors: Object.freeze({ allowedOrigins: Object.freeze([...section.cors.allowedOrigins]) }),
			}),
		httpHostSettings: ({ section }): HttpHostSettings =>
			Object.freeze({ port: section.port, readinessTimeoutMs: section.readinessTimeoutMs }),
	},
	authoritative: ["httpSettings"],
	lifecycle: { httpSettings: { eager: true }, httpHostSettings: { eager: true } },
});

/**
 * KeyStore module: owns `key-store {}` and provides the JWT signing KeyStore
 * from it through the built-in local adapter. The section moved from
 * `oauth.jwt.signingKey`, and the variables bound to it are renamed after
 * their paths (`KEY_STORE_*`). Other deployments wire their own KeyStore
 * through a module of the same shape.
 */
export const keyStoreModule: Module = defineModule({
	name: "key-store",
	section: {
		schema: keyStoreSectionSchema,
		reference: templateReference(),
		relocatedFrom: { "oauth.jwt.signingKey": "" },
		renamedVariables: {
			OAUTH_JWT_SIGNING_KEY_PROVIDER: "oauth.jwt.signingKey.provider",
			OAUTH_JWT_ALGORITHM: "oauth.jwt.signingKey.local.algorithm",
			OAUTH_JWT_KID: "oauth.jwt.signingKey.local.kid",
			OAUTH_JWT_SECRET: "oauth.jwt.signingKey.local.secret",
			OAUTH_JWT_PRIVATE_KEY_PATH: "oauth.jwt.signingKey.local.privateKeyPath",
			OAUTH_JWT_PUBLIC_KEY_PATH: "oauth.jwt.signingKey.local.publicKeyPath",
			OAUTH_JWT_PRIVATE_KEY: "oauth.jwt.signingKey.local.privateKey",
			OAUTH_JWT_PUBLIC_KEY: "oauth.jwt.signingKey.local.publicKey",
		},
	},
	provides: {
		keyStore: async ({ section }) => {
			const factory = createKeyStoreFactory();
			registerBuiltinKeyStores(factory);
			return factory.create(flattenAdapterConfig(section));
		},
	},
});

/** Which adapter fills each repository slot the `repositories` module provides. */
export interface RepositorySelection {
	readonly client: Adapters["clientRepository"];
	readonly user: Adapters["userRepository"];
}

/**
 * `block`, the settings `repositories.<repository>.<adapter>` holds. The
 * section's schema (`repositoriesSectionSchemaFor`) has refused a selected
 * `static` without its block, so an absent one is a composition that built
 * the section otherwise: an `Error` naming its path.
 */
function requiredBlock<B>(block: B | undefined, repository: string, adapter: string): B {
	if (block === undefined) {
		throw new Error(
			`repositories.${repository}.${adapter}.path must be set when adapters.${repository}Repository is "${adapter}"`,
		);
	}
	return block;
}

/**
 * Repositories module: owns `repositories {}` and provides the client and
 * user repositories the composition root's `adapters` select, through the
 * built-in adapter factories: the YAML client registry, and the YAML or the
 * Store's HTTP user repository (`@o3co/auth-provider-foundation`); core's
 * `static`, an alias of `yaml`, reads a block of its own. The
 * variables bound to its keys are renamed after their paths
 * (`REPOSITORIES_*`). `codeRepository` comes from the in-process or the Redis
 * code repository module instead.
 */
export function repositoriesModuleFor(selection: RepositorySelection): Module {
	return defineModule({
		name: "repositories",
		section: {
			schema: repositoriesSectionSchemaFor(selection),
			reference: templateReference(),
			renamedVariables: {
				CLIENT_PATH: "repositories.client.yaml.path",
				CLIENT_USER_PATH: "repositories.user.yaml.path",
				CLIENT_USER_AUTHENTICATE_URL: "repositories.user.http.authenticateUrl",
				CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL: "repositories.user.http.authenticateByTokenUrl",
				CLIENT_USER_LINK_FEDERATED_IDENTITY_URL: "repositories.user.http.linkFederatedIdentityUrl",
				CLIENT_USER_FIND_SUBJECT_BY_FEDERATED_IDENTITY_URL:
					"repositories.user.http.findSubjectByFederatedIdentityUrl",
				CLIENT_USER_BEARER_TOKEN: "repositories.user.http.bearerToken",
				CLIENT_USER_TIMEOUT: "repositories.user.http.timeout",
				CLIENT_USER_MAX_RESPONSE_BYTES: "repositories.user.http.maxResponseBytes",
			},
		},
		// Forwarded into the repository factories so client/user adapters can
		// register disposal callbacks (file-watch closers, say). Without it, a
		// builder's `ctx.lifecycle?.register` is a no-op and those resources leak.
		optional: ["lifecycleRegistrar"] as const,
		provides: {
			clientRepository: async ({ section, lifecycleRegistrar }) => {
				const { clientFactory } = createRepositoryFactories({ lifecycle: lifecycleRegistrar });
				const file = requiredBlock(section.client[selection.client], "client", selection.client);
				return clientFactory.create({
					type: selection.client,
					path: path.resolve(process.cwd(), file.path),
				});
			},
			userRepository: async ({ section, lifecycleRegistrar }) => {
				const { userFactory } = createRepositoryFactories({ lifecycle: lifecycleRegistrar });
				registerBuiltinAdapters({ userFactory });
				return userFactory.create(
					flattenAdapterConfig({
						type: selection.user,
						[selection.user]: section.user[selection.user],
					}),
				);
			},
		},
	});
}

/**
 * In-memory CodeRepository module, wired by `buildModules` only when
 * `adapters.codeRepository = "memory"`; the Redis choice swaps in
 * `redisCodeRepositoryModule` from `@o3co/auth-provider-redis` (mutually
 * exclusive: both provide the `codeRepository` slot). It reads its own
 * section, which moved from `repositories.code.memory`; the
 * `repositories.code.redis` block is removed.
 */
export const inMemoryCodeRepositoryModule: Module = defineModule({
	name: "standalone-in-memory-code-repository",
	section: {
		schema: inMemoryCodeRepositorySectionSchema,
		reference: templateReference(),
		relocatedFrom: { "repositories.code.memory": "", "repositories.code.redis": null },
		renamedVariables: {
			CLIENT_CODE_DEFAULT_EXPIRES_IN: "repositories.code.memory.defaultExpiresIn",
			CLIENT_CODE_ENDPOINT_URI: "repositories.code.redis.endpointUri",
			CLIENT_CODE_PASSWORD: "repositories.code.redis.password",
		},
	},
	// The replica-safety guard reads this off the manifest, not by module name.
	replicaSafety: {
		unsafe: true,
		reason:
			"authorization codes fork per replica — a code issued by the replica that served /authorize is unknown to the replica that receives the token request, so the exchange fails with invalid_grant everywhere but one replica, and a code redeemed on one replica can be redeemed again on another",
	},
	optional: ["lifecycleRegistrar"] as const,
	provides: {
		codeRepository: async ({ section, lifecycleRegistrar }) => {
			const { codeFactory } = createRepositoryFactories({ lifecycle: lifecycleRegistrar });
			return codeFactory.create({ type: "memory", defaultExpiresIn: section.defaultExpiresIn });
		},
	},
});

/**
 * In-memory user-session stores module: the four-store user-session split
 * (userSessionStore, sessionRPRegistry, sessionFamilyIndex,
 * sessionFederationIndex) and the subject-level revocation pair. Wired by
 * `buildModules` only when `adapters.userSessionStores = "memory"`; the Redis
 * branch swaps in `redisSessionStoresModule` from `@o3co/auth-provider-redis`.
 */
export const inMemorySessionStoresModule: Module = defineModule({
	name: "standalone-in-memory-session-stores",
	replicaSafety: {
		unsafe: true,
		reason:
			"user sessions, RP registrations, family indexes and the subject-level revocation pair fork per replica — back-channel logout reaches only the replica that received it, so a logged-out session stays valid on the others, and a credential change enumerates and watermarks only the replica that handled it",
	},
	provides: {
		userSessionStore: () => createInMemoryUserSessionStore(),
		sessionRPRegistry: () => createInMemorySessionRPRegistry(),
		sessionFamilyIndex: () => createInMemorySessionFamilyIndex(),
		sessionFederationIndex: () => createInMemorySessionFederationIndex(),
		// The subject-level revocation slots. Without them `subjectRevocation`
		// is undefined: `verifyJwt` skips the watermark, the refresh gate is
		// inert and `revokeAllForSubject` reports `unavailable`, all silently.
		// The boot guard refuses that state; the scaffold wires them rather than
		// declaring the capability absent. Single-process only, like every
		// other store on this branch.
		subjectSessionIndex: () => createInMemorySubjectSessionIndex(),
		subjectRevocation: () => createInMemorySubjectRevocation(),
	},
});

/**
 * In-memory federation token store module, wired by `buildModules` only when
 * `adapters.federationTokenStore = "memory"` (the default). The redis branch
 * swaps in `redisFederationTokenStoreModule` off the shared ioredis socket
 * (mutually exclusive: both provide the `federationTokenStore` slot). One
 * module per adapter, so the replica-safety guard can tell them apart and the
 * Redis one can require its client. The slot is always wired, independent of
 * the `adapters.userSessionStores` selection.
 *
 * The memory adapter comes through core's factory: that is where its
 * "dev/test only" boot warning lives.
 */
export const inMemoryFederationTokenStoreModule: Module = defineModule({
	name: "standalone-in-memory-federation-token-store",
	replicaSafety: {
		unsafe: true,
		reason:
			"upstream federation tokens fork per replica — a token stored by the replica that completed the federation callback is missing on the others, so a session cannot refresh its upstream token from another replica, and logout removes only the tokens the replica it lands on can see",
	},
	provides: {
		federationTokenStore: async () => {
			const factory = createFederationTokenStoreFactory();
			registerBuiltinFederationTokenStores(factory);
			return factory.create({ type: "memory" });
		},
	},
});

/**
 * Audit-sink module: owns `audit-sink {}` and fills the `auditSink` slot every
 * route that emits a security event reads, with the sink the composition
 * root's `adapters.auditSink` names: the template's `"logger"` (its default)
 * or one of core's built-ins, with that sink's options from
 * `audit-sink.<name>`. The slot is `optional` on `oauthModule`,
 * `sessionModule` and `webauthnModule`, and `emitAuditEvent` is a no-op when
 * it is empty, so this module is always in the manifest; a name no builder is
 * registered under refuses boot. The sink's options moved from `audit.sink`.
 *
 * `createAuditSinkFactory()` takes no `BuilderContext`, so a sink builder
 * receives `{}` and the `ctx.lifecycle?.register(…)` /
 * `ctx.readiness?.register(…)` calls CONTRIBUTING.md requires of a builder
 * opening a connection are silent no-ops: a sink holding a socket must own
 * its cleanup another way.
 */
export function auditSinkModuleFor(sink: string): Module {
	return defineModule({
		name: "audit-sink",
		section: {
			schema: auditSinkSectionSchema,
			reference: templateReference(),
			relocatedFrom: {
				"audit.sink": { to: "", environmentVariable: null },
				"audit.sink.type": null,
			},
		},
		provides: {
			auditSink: async ({ section }) => {
				const factory = createAuditSinkFactory();
				registerBuiltinAuditSinks(factory);
				factory.register("logger", () => createLoggerAuditSink(createAuditLogger()));
				return factory.create(flattenAdapterConfig({ type: sink, [sink]: section?.[sink] }));
			},
		},
	});
}

/**
 * @deprecated Split into `inMemorySessionStoresModule` and
 * `inMemoryFederationTokenStoreModule`; use those. Kept for consumers that
 * imported `storesModule` from this file.
 */
export const storesModule: Module = defineModule({
	name: "stores",
	// Everything this bundle provides lives in process memory, so a
	// composition still on it is refused under `core.deployment.mode = "multi"`
	// like the split modules it stands in for.
	replicaSafety: {
		unsafe: true,
		reason:
			"user sessions, RP registrations, family indexes, the subject-level revocation pair and upstream federation tokens fork per replica — back-channel logout reaches only the replica that received it, so a logged-out session stays valid on the others",
	},
	requires: ["config"] as const,
	provides: {
		...inMemorySessionStoresModule.provides,
		...inMemoryFederationTokenStoreModule.provides,
	},
});

/**
 * Shared ioredis clients module: opens ONE long-lived ioredis connection per
 * replica and derives every per-purpose client from it (`makeIoredisClients`,
 * plus the two federation-grant store clients from their own factories),
 * rather than a socket per Redis-backed module, to keep connection-pool
 * pressure off the upstream Redis. Every store module
 * `@o3co/auth-provider-redis` ships finds its client slot here, including
 * those this template does not select; `all-modules-composition.multi.test.mts`
 * pins that.
 *
 * The connection's URL and password are the module's own section,
 * `redis-clients`, which moved from `refreshTokenFamilyStore.redis` with its
 * variables (`REDIS_CLIENTS_*`). Per-store Redis instances belong in a
 * custom composition root. An empty URL throws rather than falling back to
 * localhost. `io.quit()` is registered once with `lifecycleRegistrar`, so
 * `handle.dispose()` closes the connection.
 *
 * `buildModules` adds this module only when some composed module needs a
 * Redis client (`usingRedisAnywhere`), so memory-only compositions open no
 * socket.
 */
export const standaloneRedisClientsModule: Module = defineModule({
	name: "redis-clients",
	section: {
		schema: redisClientsSectionSchema,
		reference: templateReference(),
		relocatedFrom: { "refreshTokenFamilyStore.redis": "" },
		renamedVariables: {
			REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: "refreshTokenFamilyStore.redis.url",
			REFRESH_TOKEN_FAMILY_STORE_REDIS_PASSWORD: "refreshTokenFamilyStore.redis.password",
		},
	},
	optional: ["lifecycleRegistrar", "readinessRegistrar", "logger"] as const,
	provides: {
		refreshTokenFamilyClient: async ({
			section,
			lifecycleRegistrar,
			readinessRegistrar,
			logger,
		}) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.refreshTokenFamilyClient;
		},
		userSessionStoreClient: async ({ section, lifecycleRegistrar, readinessRegistrar, logger }) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.userSessionStoreClient;
		},
		sessionRPRegistryClient: async ({
			section,
			lifecycleRegistrar,
			readinessRegistrar,
			logger,
		}) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.sessionRPRegistryClient;
		},
		sessionFamilyIndexClient: async ({
			section,
			lifecycleRegistrar,
			readinessRegistrar,
			logger,
		}) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.sessionFamilyIndexClient;
		},
		sessionFederationIndexClient: async ({
			section,
			lifecycleRegistrar,
			readinessRegistrar,
			logger,
		}) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.sessionFederationIndexClient;
		},
		// The grant store and the intent store, consumed by the Redis grant
		// modules when their switches say "redis". Provided whenever this module
		// is installed, as every slot here is: a slot is cheap, the socket is
		// the cost.
		federationGrantStoreClient: async ({
			section,
			lifecycleRegistrar,
			readinessRegistrar,
			logger,
		}) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.federationGrantStoreClient;
		},
		federationGrantIntentStoreClient: async ({
			section,
			lifecycleRegistrar,
			readinessRegistrar,
			logger,
		}) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.federationGrantIntentStoreClient;
		},
		// The replay seen-set behind private_key_jwt client assertions.
		replaySeenSetClient: async ({ section, lifecycleRegistrar, readinessRegistrar, logger }) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.replaySeenSetClient;
		},
		rateLimiterClient: async ({ section, lifecycleRegistrar, readinessRegistrar, logger }) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.rateLimiterClient;
		},
		// `redisCodeRepositoryModule` consumes this slot when
		// `adapters.codeRepository = "redis"`.
		codeRepositoryClient: async ({ section, lifecycleRegistrar, readinessRegistrar, logger }) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.codeRepositoryClient;
		},
		// A denylist is only worth having if every replica reads the same one,
		// so it belongs on the connection the rest of the shared state uses
		// rather than a second one.
		accessTokenDenylistClient: async ({
			section,
			lifecycleRegistrar,
			readinessRegistrar,
			logger,
		}) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.accessTokenDenylistClient;
		},
		// The subject-level revocation pair, both required by
		// `redisSessionStoresModule`: the index enumerates what a credential
		// change cascades over, the watermark refuses what the cascade missed.
		// Nothing in the standalone consumes them directly; they exist so that
		// module can be selected.
		subjectSessionIndexClient: async ({
			section,
			lifecycleRegistrar,
			readinessRegistrar,
			logger,
		}) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.subjectSessionIndexClient;
		},
		subjectRevocationClient: async ({
			section,
			lifecycleRegistrar,
			readinessRegistrar,
			logger,
		}) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.subjectRevocationClient;
		},
		// Required by `redisDeviceCodeStoreModule`. This template does not mount
		// the device grant; the slot is provided anyway, so a deployment that
		// adds `deviceGrantModule` with the Redis store is not refused at boot
		// (`missing-required-component`) for a client slot nothing provided.
		deviceCodeStoreClient: async ({ section, lifecycleRegistrar, readinessRegistrar, logger }) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.deviceCodeStoreClient;
		},
		// The WebAuthn challenge store's client, for the device-code slot's
		// reason: this template does not mount WebAuthn, and a deployment that
		// adds `webauthnModule` with `redisChallengeStoreModule` would otherwise
		// be refused at boot for a `challengeStoreClient` nothing provided.
		challengeStoreClient: async ({ section, lifecycleRegistrar, readinessRegistrar, logger }) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.challengeStoreClient;
		},
		// The consent stores' clients. `redisConsentStoreModule` requires both
		// (it provides the consent records and the parked requests together),
		// and `buildModules` selects it under `adapters.consentStore = "redis"`.
		consentStoreClient: async ({ section, lifecycleRegistrar, readinessRegistrar, logger }) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.consentStoreClient;
		},
		pendingConsentStoreClient: async ({
			section,
			lifecycleRegistrar,
			readinessRegistrar,
			logger,
		}) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.pendingConsentStoreClient;
		},
		// Required by `redisFederationTokenStoreModule`.
		federationTokenStoreClient: async ({
			section,
			lifecycleRegistrar,
			readinessRegistrar,
			logger,
		}) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.federationTokenStoreClient;
		},
		// The two MFA stores' clients, required by `redisMfaFactorStoreModule`
		// and `redisMfaTransactionStoreModule`. This template installs
		// neither; the slots are provided anyway, for the device-code slot's
		// reason. Each module checks the server's eviction
		// policy and persistence when it boots (ADR
		// 2026-09-25-multi-factor-authentication).
		mfaFactorStoreClient: async ({ section, lifecycleRegistrar, readinessRegistrar, logger }) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.mfaFactorStoreClient;
		},
		mfaTransactionStoreClient: async ({
			section,
			lifecycleRegistrar,
			readinessRegistrar,
			logger,
		}) => {
			return getOrCreateClients(section, lifecycleRegistrar, readinessRegistrar, logger)
				.mfaTransactionStoreClient;
		},
	},
});

/**
 * Failure-timing options for the one shared ioredis socket. Each value's
 * reason, and the trade the offline queue buys, is in
 * `docs/operator-runbook.md`, "Failure timing on the shared socket". In
 * short: on the driver's defaults a partition produces *waiting*, not errors,
 * so the Redis limiter's `redis-rate-limiter.failMode = "closed"` policy, which the
 * guard (`createRateLimitGuard`) applies only when `limiter.check()` rejects,
 * never engages.
 * `commandTimeout` bounds every command, queued or on the wire, zombie socket
 * included; `maxRetriesPerRequest` bounds the offline queue's depth; the
 * queue stays on because the option is per connection and this socket also
 * carries sessions, codes and refresh rotation.
 *
 * One second is ample: the socket's commands are O(1) primitives and small
 * paged scans (`SET`/`GET`/`DEL`/`EXISTS`/`PTTL`/`INCR`/`EVAL`/`HSCAN`/
 * `SSCAN`/`ZADD`/…), none blocking. `lazyConnect: false` is the driver
 * default, declared so the boot-time-connect contract survives a future flip.
 */
const SHARED_REDIS_TIMEOUTS = {
	commandTimeout: 1_000,
	connectTimeout: 5_000,
	maxRetriesPerRequest: 3,
	enableOfflineQueue: true,
	lazyConnect: false,
} as const;

/**
 * Every per-purpose client off the one socket: the general bundle, plus the
 * two the federation-grant stores need. Those two have their own factories in
 * the Redis package, so a Cluster deployment can give the grants a
 * connection of their own; this template shares the socket, as it does for
 * every other store.
 */
type StandaloneRedisClients = ReturnType<typeof makeIoredisClients> & {
	readonly federationGrantStoreClient: ReturnType<typeof makeIoredisFederationGrantStoreClient>;
	readonly federationGrantIntentStoreClient: ReturnType<
		typeof makeIoredisFederationGrantIntentStoreClient
	>;
};
// So every `provides.*` factory reuses one `Redis` instance (and its clients)
// within a createApp() call, rather than opening a socket per consumed slot.
// Keyed on the `lifecycleRegistrar` identity, fresh per boot: keying on
// `config` would share connections across boots that reuse a config object,
// and only the first boot's registrar would dispose them. Without a
// registrar (tests that seed none), each call creates a fresh client.
const clientsCache = new WeakMap<LifecycleRegistrar, StandaloneRedisClients>();
function getOrCreateClients(
	section: { readonly url: string; readonly password?: string | undefined },
	lifecycleRegistrar: LifecycleRegistrar | undefined,
	readinessRegistrar?: ReadinessRegistrar,
	injectedLogger?: Logger,
): StandaloneRedisClients {
	const logger = injectedLogger ?? consoleLogger;
	const cached = lifecycleRegistrar ? clientsCache.get(lifecycleRegistrar) : undefined;
	if (cached) return cached;

	if (section.url.length === 0) {
		throw new Error(
			"standaloneRedisClientsModule: `redis-clients.url` is required when any " +
				"Redis-backed adapter is selected. Set REDIS_CLIENTS_URL, or the " +
				"key in a configuration layer, to a non-empty URL. Multi-replica deployments require " +
				"a shared Redis 7.2+ instance.",
		);
	}

	const io = new Redis(section.url, { password: section.password, ...SHARED_REDIS_TIMEOUTS });

	// Attach an error handler so unhandled "error" events do not crash the
	// process. Initial connection failures surface here; downstream adapter
	// operations then fail visibly. It logs the projection: ioredis puts the
	// command a reply answered on the error, and for a refused handshake that
	// is `AUTH` with the configured password.
	io.on("error", (err: unknown) => {
		logger.error({ err: loggableError(err) }, "standalone_redis_clients_error");
	});

	lifecycleRegistrar?.register(async () => {
		await io.quit();
	});

	// One probe for the one socket, not one per consumed slot: the cache
	// above means this runs once per boot, on the call that constructs the
	// client.
	readinessRegistrar?.register({
		name: "redis",
		check: () => io.ping(),
	});

	// The wrapper opens its own connections for refresh rotation
	// (`refreshTokenFamilyClient.duplicate()`), which inherit no listeners from
	// `io`; passing the logger lets those report through the same channel.
	const clients: StandaloneRedisClients = {
		...makeIoredisClients(io, { logger }),
		federationGrantStoreClient: makeIoredisFederationGrantStoreClient(io),
		federationGrantIntentStoreClient: makeIoredisFederationGrantIntentStoreClient(io),
	};
	if (lifecycleRegistrar) clientsCache.set(lifecycleRegistrar, clients);
	return clients;
}

/**
 * Reads an optional string field off a federation slice. An unset field stays
 * absent rather than becoming `undefined`, so `"sessionDomain" in config`
 * still distinguishes the two. A present non-string throws: HOCON hands
 * through whatever the file holds, and silently ignoring `sessionDomain = 42`
 * would run the redirect policy with one fewer constraint than the operator
 * wrote down.
 */
function optionalString(
	slice: Record<string, unknown>,
	field: string,
): Record<string, string> | Record<string, never> {
	const value = slice[field];
	if (value === undefined || value === null) return {};
	if (typeof value !== "string") {
		throw new Error(`core.federations.google.${field} must be a string when present`);
	}
	return { [field]: value };
}

/**
 * An optional boolean from the `core.federations.google` entry: a HOCON boolean, or
 * from an environment override (`${?VAR}`) a string in the spellings core's
 * `coerceBooleanFromEnv` accepts ("true" / "false" / "1" / "0", trimmed, any
 * case). Unlike that coercion, an empty value is refused, not read as false:
 * HOCON substitutes an exported-but-empty variable as "", and a security
 * switch must not quietly turn the check off. Anything else is refused too,
 * so a typo fails boot rather than reading as either value.
 */
function optionalBoolean(
	slice: Record<string, unknown>,
	field: string,
): Record<string, boolean> | Record<string, never> {
	const value = slice[field];
	if (value === undefined || value === null) return {};
	if (typeof value === "boolean") return { [field]: value };
	if (typeof value === "string") {
		const normalized = value.trim().toLowerCase();
		if (normalized === "true" || normalized === "1") return { [field]: true };
		if (normalized === "false" || normalized === "0") return { [field]: false };
	}
	throw new Error(
		`core.federations.google.${field} must be one of true, false, "true", "false", "1" or "0" when present`,
	);
}

/**
 * `accessType` from the `core.federations.google` entry: `"offline"` or `"online"`,
 * exactly, or absent. `federation-google` refuses any other value too; this
 * refuses it first, naming the key, as the fields above do.
 */
function optionalAccessType(
	slice: Record<string, unknown>,
): { accessType: "offline" | "online" } | Record<string, never> {
	const value = slice.accessType;
	if (value === undefined || value === null) return {};
	if (value === "offline" || value === "online") return { accessType: value };
	throw new Error('core.federations.google.accessType must be "offline" or "online" when present');
}

/**
 * Google federation config bridge: supplies the typed `googleFederationConfig`
 * slot from the `core.federations.google` entry. The bridge is the
 * composition root's responsibility because the slot's content is
 * consumer-specific (see the `@o3co/auth-provider-federation-google` README).
 *
 * It carries every field the provider reads, not only the credentials:
 * `googleFederationModule` hands this same object to
 * `createFederationRedirectPolicy`, so a dropped `redirectAllowlist` /
 * `sessionDomain` / `authCallbackUrl` / `clientUrl` would silently run the
 * policy without the constraints the operator configured.
 */
export const googleFederationConfigModule: Module = defineModule({
	name: "google-federation-config",
	requires: ["config"] as const,
	provides: {
		googleFederationConfig: ({ config }): GoogleProviderConfig => {
			const slice = extractFederationSection(federationsOf(config), "google");
			if (!slice) {
				throw new Error(
					"core.federations.google must be enabled with credentials when googleFederationModule is in the manifest",
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
					"core.federations.google requires clientId, clientSecret, callbackURL when enabled",
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
						"core.federations.google.redirectAllowlist must be a list of URL strings, " +
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
				// Absent means the provider's default, which is to require it.
				...optionalBoolean(slice, "requireAuthorizationResponseIss"),
				// Absent means the provider's default, "offline": consent on every
				// sign-in, and a refresh token for every session.
				...optionalAccessType(slice),
			};
		},
	},
});

/**
 * OIDC federation config bridge: supplies the `oidcFederationConfigs`
 * slot every `oidcFederationModule(<name>)` in the manifest reads its entry
 * from. One bridge for all instances: `readOidcFederationConfigs` walks
 * `core.federations` and reads every enabled entry of type `oidc`,
 * refusing a malformed field by `core.federations.<name>.<field>` at boot.
 * `buildModules` lists this module only when at least one such section
 * exists.
 */
export const oidcFederationConfigModule: Module = defineModule({
	name: "oidc-federation-config",
	requires: ["config"] as const,
	provides: {
		oidcFederationConfigs: ({ config }) => readOidcFederationConfigs(federationsOf(config)),
	},
});
