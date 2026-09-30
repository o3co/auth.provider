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
	consoleLogger,
	defaultRefreshTokenFamilyRevocationModule,
	defaultRefreshTokenFamilyRotationModule,
	jwksModule,
	type Logger,
	type Module,
	memoryAccessTokenDenylistModule,
	memoryConsentStoreModule,
	memoryFederationGrantIntentStoreModule,
	memoryFederationGrantStoreModule,
	memoryRateLimiterModule,
	memoryReplaySeenSetModule,
} from "@o3co/auth-provider-core";
import { googleFederationModule } from "@o3co/auth-provider-federation-google";
import { federationGrantsModules } from "@o3co/auth-provider-federation-grants";
import { oidcFederationModule, oidcFederationNames } from "@o3co/auth-provider-federation-oidc";
import {
	oauthAuthorizationModule,
	oauthModule,
	oauthSessionModule,
	subjectRevocationServiceModule,
} from "@o3co/auth-provider-oauth";
import {
	redisAccessTokenDenylistModule,
	redisCodeRepositoryModule,
	redisConsentStoreModule,
	redisFederationGrantIntentStoreModule,
	redisFederationGrantStoreModuleFor,
	redisFederationTokenStoreModuleFor,
	redisRateLimiterModule,
	redisRefreshTokenFamilyStoreModule,
	redisReplaySeenSetModule,
	redisSessionStoresModule,
} from "@o3co/auth-provider-redis";
import {
	extractFederationSection,
	sessionModule,
	sessionStoreModuleFor,
} from "@o3co/auth-provider-session";
import {
	auditSinkModule,
	corsModule,
	googleFederationConfigModule,
	httpModule,
	inMemoryCodeRepositoryModule,
	inMemoryFederationTokenStoreModule,
	inMemorySessionStoresModule,
	keyStoreModule,
	loggingModule,
	oidcFederationConfigModule,
	repositoriesModule,
	standaloneRedisClientsModule,
} from "./modules.mjs";

/**
 * Overrides for the composition. All but `environment` and `logger` are
 * test-only: they let the smoke test substitute in-memory implementations of
 * the file-system-backed modules, and production callers should not pass them
 * — the defaults match the standalone scaffold.
 */
export interface BuildModulesOverrides {
	/**
	 * The name this deployment selected its configuration by (`CONFIG_ENV ||
	 * NODE_ENV`, computed once in `app.mts`), so the Redis federation-token
	 * store's `allow-plaintext` guard reads the environment the config came
	 * from, not `NODE_ENV` alone. Omitted, the guard falls back to `NODE_ENV`
	 * (and the `deploymentMode` slot core fills from `deployment.mode`, which it
	 * reads either way).
	 */
	readonly environment?: string;
	/**
	 * Where the composition's own notices go — a deprecated config key, one
	 * `config_key_deprecated` line (warn) each. `app.mts` passes the logger it
	 * hands every module; omitted, `consoleLogger`.
	 */
	readonly logger?: Logger;
	readonly keyStoreModule?: Module;
	readonly repositoriesModule?: Module;
	readonly storesModule?: Module;
	/**
	 * Replaces the refresh-token family store modules (default
	 * `[redisRefreshTokenFamilyStoreModule]`, on the shared ioredis socket).
	 * Tests that must not open an ioredis connection pass
	 * `[memoryRefreshTokenFamilyStoreModule]`.
	 */
	readonly refreshTokenFamilyModules?: readonly Module[];
	/**
	 * Replaces the module filling the `auditSink` slot (the default writes the
	 * trail to stdout); tests substitute a sink they can assert on. It replaces
	 * rather than adds, since a second provider would be a boot-time slot
	 * collision. There is no way to pass "no audit sink": pass one that discards.
	 */
	readonly auditSinkModule?: Module;
}

/**
 * The access-token lifetime core's `reference.conf` ships on the deprecated
 * `oauth.accessToken.expiresIn`. Not a default — nothing mints with it — only
 * what an unmodified deployment carries there, so the deprecation line can tell
 * an operator's override from the shipped value. Pinned against the real file
 * by `access-token-lifetime-alias.test.mts`.
 */
const SHIPPED_ACCESS_TOKEN_EXPIRES_IN = 3600;

/**
 * Compose the standalone module list from `config`. Kept out of `app.mts` so
 * a smoke test can check the manifest (that disabling a federation removes
 * its module pair, say) without an HTTP server. The rules for editing the
 * list (order, one module per store slot, federation adapters with their
 * config bridges) are in the template README, "Module Composition Order".
 */
export function buildModules(config: AppConfig, overrides: BuildModulesOverrides = {}): Module[] {
	// A section's `type` names the implementation, so the two gates never both
	// select one section: `federations.google` is the built-in Google
	// federation only when its type is `google` (that name's default); with
	// `type = "oidc"` it is a generic OIDC instance, and composing both would
	// contribute the same federation and redirect-policy keys twice.
	const googleEnabled =
		extractFederationSection(config.federations ?? {}, "google")?.type === "google";
	const oidcFederations = oidcFederationNames(config.federations ?? {});
	const logger = overrides.logger ?? consoleLogger;

	// Adapter switches. When ANY is `"redis"`, or the refresh-token family
	// modules keep the Redis store (the default), the shared
	// `standaloneRedisClientsModule` is added once, one ioredis socket per
	// replica; memory-only deployments open none.
	const rateLimiterAdapter = config.rateLimiter?.adapter ?? "memory";
	const userSessionStoresAdapter = config.userSessionStores?.adapter ?? "memory";
	// The RFC 7009 access-token denylist has no "none" branch: `oauthModule`
	// mounts `/oauth/revoke` and reads the `accessTokenDenylist` slot, and core's
	// boot validator refuses a composition that reads the slot with nothing
	// filling it, since the endpoint would answer 200 while the token kept
	// working. The switch is only over WHICH denylist.
	const accessTokenDenylistAdapter = config.accessTokenDenylist?.adapter ?? "memory";
	// The jti single-use record behind private_key_jwt client auth.
	const replaySeenSetAdapter = config.replaySeenSet?.adapter ?? "memory";
	// The consent store behind /authorize for clients that are not first-party.
	// `"none"` (the default) wires nothing and such clients are refused, so a
	// first-party-only deployment pays nothing and a multi-replica one is not
	// handed a memory store it cannot run; that one selects `"redis"`.
	const consentStoreAdapter = config.consentStore?.adapter ?? "none";
	// The federation token store: `"memory"` by default, the local-dev shape;
	// `"redis"` mounts `redisFederationTokenStoreModule` off the shared socket.
	const federationTokenStoreAdapter = config.federationTokenStore?.type ?? "memory";
	// Federation grants: a user's standing consent that a client may obtain
	// upstream tokens with no session behind the call. Off by default, and off
	// installs nothing: no store, no socket, no boot requirement. On, the routes
	// and the background registry the shutdown drains come as a pair; each store
	// follows its own switch (grants in Redis with acquisition in memory is a
	// supported single-replica shape); and the subject-revocation service is
	// installed, whose `federationGrantStore` edge makes "revoke everything this
	// subject holds" include the grants. Enabling it also states the deployment
	// has a consent page, a callback per connection and a user repository
	// covering each connection's registration; the routes module refuses at
	// boot what is missing, naming it.
	const federationGrantsEnabled = config.federationGrants?.enabled === true;
	const federationGrantStoreAdapter = config.federationGrantStore?.adapter ?? "memory";
	const federationGrantIntentStoreAdapter = config.federationGrantIntentStore?.adapter ?? "memory";

	// `oauth.code.adapter` is authoritative; the deprecated
	// `repositories.code.type = "redis"` (`CLIENT_CODE_TYPE=redis`) is still
	// honoured, with a deprecation warning. See CHANGELOG for the removal
	// version.
	const oauthCodeAdapter = config.oauth?.code?.adapter;
	const legacyCodeType = (config.repositories?.code as { type?: string } | undefined)?.type;
	let codeRepositoryAdapter: "memory" | "redis";
	if (oauthCodeAdapter !== undefined) {
		codeRepositoryAdapter = oauthCodeAdapter;
	} else if (legacyCodeType === "redis") {
		logger.warn(
			{
				key: "repositories.code.type",
				env: "CLIENT_CODE_TYPE",
				replacement: "oauth.code.adapter",
				replacementEnv: "OAUTH_CODE_ADAPTER",
			},
			"config_key_deprecated",
		);
		codeRepositoryAdapter = "redis";
	} else {
		codeRepositoryAdapter = "memory";
	}

	// The deprecated alias `oauth.accessToken.expiresIn`
	// (OAUTH_ACCESS_TOKEN_EXPIRES_IN) is still read as the default while
	// `defaultExpiresIn` is unset; `resolveAccessTokenLifetime` does that, and
	// this only warns. Core's `reference.conf` ships the lifetime on the
	// deprecated key, so only an override of it has something to move. See
	// CHANGELOG for the removal version.
	const accessToken = config.oauth.accessToken;
	if (
		accessToken.defaultExpiresIn === undefined &&
		accessToken.expiresIn !== SHIPPED_ACCESS_TOKEN_EXPIRES_IN
	) {
		logger.warn(
			{
				key: "oauth.accessToken.expiresIn",
				env: "OAUTH_ACCESS_TOKEN_EXPIRES_IN",
				replacement: "oauth.accessToken.defaultExpiresIn",
				replacementEnv: "OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN",
			},
			"config_key_deprecated",
		);
	}

	const refreshTokenFamilyModules: readonly Module[] = overrides.refreshTokenFamilyModules ?? [
		redisRefreshTokenFamilyStoreModule,
	];
	// Whether the family modules keep the Redis-backed store (the default
	// does). Without the shared clients module added for it, that store fails
	// boot on the missing `refreshTokenFamilyClient` component.
	const refreshTokenFamilyUsesRedis = refreshTokenFamilyModules.some(
		(m) => m.name === "redis-refresh-token-family-store",
	);
	const usingRedisAnywhere =
		refreshTokenFamilyUsesRedis ||
		rateLimiterAdapter === "redis" ||
		userSessionStoresAdapter === "redis" ||
		codeRepositoryAdapter === "redis" ||
		accessTokenDenylistAdapter === "redis" ||
		replaySeenSetAdapter === "redis" ||
		consentStoreAdapter === "redis" ||
		federationTokenStoreAdapter === "redis" ||
		// Only while the feature is on: a switch left at "redis" for a feature
		// that is off must not open a socket.
		(federationGrantsEnabled &&
			(federationGrantStoreAdapter === "redis" || federationGrantIntentStoreAdapter === "redis"));

	// The four user-session stores switch on `userSessionStores.adapter`; the
	// federation-token store is always wired and switches on its own key below.
	const sessionStoresModules: Module[] =
		userSessionStoresAdapter === "redis"
			? [redisSessionStoresModule]
			: overrides.storesModule
				? [overrides.storesModule]
				: [inMemorySessionStoresModule];

	const rateLimiterModules: Module[] =
		rateLimiterAdapter === "redis" ? [redisRateLimiterModule] : [memoryRateLimiterModule];

	// Mutually exclusive: both modules provide the `codeRepository` slot, and
	// including both would be a boot-time slot collision.
	const codeRepositoryModules: Module[] =
		codeRepositoryAdapter === "redis"
			? [redisCodeRepositoryModule]
			: [inMemoryCodeRepositoryModule];

	// The memory denylist is a dev convenience and nothing more: it forks per
	// replica, so `deployment.mode = "multi"` refuses it by name (core's
	// replica-safety guard). The template's own application.conf ships `"redis"`.
	const accessTokenDenylistModules: Module[] =
		accessTokenDenylistAdapter === "redis"
			? [redisAccessTokenDenylistModule]
			: [memoryAccessTokenDenylistModule];

	// Opt-in. Each module provides both slots the consent step needs (the
	// consent records and the requests parked while the page asks), so the two
	// cannot be wired apart. The memory one declares itself replica-unsafe and
	// `deployment.mode = "multi"` refuses it by name; the Redis one shares both
	// over the ioredis socket.
	const consentStoreModules: Module[] =
		consentStoreAdapter === "redis"
			? [redisConsentStoreModule]
			: consentStoreAdapter === "memory"
				? [memoryConsentStoreModule]
				: [];

	const replaySeenSetModules: Module[] =
		replaySeenSetAdapter === "redis" ? [redisReplaySeenSetModule] : [memoryReplaySeenSetModule];

	// One federation-token-store module per adapter, so the memory one can
	// declare `replicaSafety` on its manifest and the Redis one can `require`
	// its client slot. The Redis module is built for this composition root so
	// its plaintext guard knows which environment selected the config; it
	// reads the replica count from core's `deploymentMode` slot.
	const federationTokenStoreModules: Module[] =
		federationTokenStoreAdapter === "redis"
			? [redisFederationTokenStoreModuleFor({ environment: overrides.environment })]
			: [inMemoryFederationTokenStoreModule];

	// One module per store, nothing while the feature is off. The Redis grant
	// store is built for this composition root so its plaintext guard knows
	// which environment selected the config, as the federation-token store's
	// is. Both memory modules declare `replicaSafety`, so `deployment.mode =
	// "multi"` refuses them by name; the routes module itself refuses a Redis
	// grant store beside memory user-session stores, because the grants would
	// outlive the boundary that ends them.
	const federationGrantStoreModules: Module[] = !federationGrantsEnabled
		? []
		: federationGrantStoreAdapter === "redis"
			? [
					overrides.environment === undefined
						? redisFederationGrantStoreModuleFor()
						: redisFederationGrantStoreModuleFor({ environment: overrides.environment }),
				]
			: [memoryFederationGrantStoreModule];
	const federationGrantIntentStoreModules: Module[] = !federationGrantsEnabled
		? []
		: federationGrantIntentStoreAdapter === "redis"
			? [redisFederationGrantIntentStoreModule]
			: [memoryFederationGrantIntentStoreModule];

	return [
		// MUST stay first: it declares no `before`/`after`, so this position is
		// what mounts express-session ahead of every session-consuming module.
		// Built from `config` so that `session.storage.type = "memory"` declares
		// itself replica-unsafe and `deployment.mode = "multi"` refuses it.
		sessionStoreModuleFor(config),
		// Under `/oauth` beside `oauthModule`, each parsing its own requests, so
		// their relative order does not matter; the browser half orders itself
		// after the session middleware by its own `after`.
		...(federationGrantsEnabled ? federationGrantsModules : []),
		oauthModule({ config }),
		oauthSessionModule({ config }),
		oauthAuthorizationModule({ config }),
		// Always wired: a provider that signs tokens must publish its
		// verification keys regardless of OIDC issuer config, and `oauthModule`'s
		// discovery `jwks_uri` (advertised when an issuer is set) must resolve.
		jwksModule,
		sessionModule,
		...(googleEnabled ? [googleFederationModule, googleFederationConfigModule] : []),
		...(oidcFederations.length > 0
			? [oidcFederationConfigModule, ...oidcFederations.map((name) => oidcFederationModule(name))]
			: []),
		// The template's own settings: `logging {}`, `http {}` and `cors {}`.
		loggingModule,
		httpModule,
		corsModule,
		overrides.keyStoreModule ?? keyStoreModule,
		overrides.repositoriesModule ?? repositoriesModule,
		// The audit sink, always wired: `emitAuditEvent` no-ops on an empty slot,
		// so the routes' security events (`token.issued.failure`,
		// `authorize.rejected`, `rate_limit.unavailable`, …) would go nowhere.
		// Which sink is a config question (`audit.sink.type`); whether there is
		// one is not.
		overrides.auditSinkModule ?? auditSinkModule,
		...(usingRedisAnywhere ? [standaloneRedisClientsModule] : []),
		...federationTokenStoreModules,
		...federationGrantStoreModules,
		...federationGrantIntentStoreModules,
		...sessionStoresModules,
		...rateLimiterModules,
		...codeRepositoryModules,
		...accessTokenDenylistModules,
		...replaySeenSetModules,
		...consentStoreModules,
		...refreshTokenFamilyModules,
		defaultRefreshTokenFamilyRotationModule,
		defaultRefreshTokenFamilyRevocationModule,
		// The composed "end everything this subject holds" a credential change
		// calls, reached as `handle.components.subjectRevocationService`.
		// Installed with the feature, which is what makes it reach the grants;
		// without grants a Store calls core's revokeAllForSubject.
		...(federationGrantsEnabled ? [subjectRevocationServiceModule] : []),
	];
}
