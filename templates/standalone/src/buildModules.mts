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
import { googleFederationTypeModule } from "@o3co/auth-provider-federation-google";
import { federationGrantsModules } from "@o3co/auth-provider-federation-grants";
import { oidcFederationTypeModule } from "@o3co/auth-provider-federation-oidc";
import {
	oauthAuthorizationModule,
	oauthModule,
	oauthSessionGrantModule,
	subjectRevocationServiceModule,
} from "@o3co/auth-provider-oauth";
import {
	redisAccessTokenDenylistModule,
	redisAttemptCounterModule,
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
import { sessionModule, sessionStoreModuleFor } from "@o3co/auth-provider-session";
import {
	standardDevelopmentMailSenderModule,
	standardSmtpMailSenderModule,
} from "@o3co/auth-provider-standard";
import type { Switches } from "./configPath.mjs";
import { mfaModulesFor } from "./mfaSwitch.mjs";
import {
	auditSinkModuleFor,
	httpModule,
	inMemoryCodeRepositoryModule,
	inMemoryFederationTokenStoreModule,
	inMemorySessionStoresModule,
	keyStoreModule,
	loggingModule,
	repositoriesModuleFor,
	standaloneRedisClientsModule,
} from "./modules.mjs";

/**
 * Overrides for the composition. All but `environment`, `logger` and
 * `mailSenderModules` are test-only: they let the smoke test substitute
 * in-memory implementations of the file-system-backed modules, and production
 * callers should not pass them — the defaults match the standalone scaffold.
 */
export interface BuildModulesOverrides {
	/**
	 * The name this deployment selected its configuration by (`CONFIG_ENV ||
	 * NODE_ENV`, computed once in `app.mts`), so the Redis federation-token
	 * store's `allow-plaintext` guard reads the environment the config came
	 * from, not `NODE_ENV` alone. Omitted, the guard falls back to `NODE_ENV`
	 * (and the `deploymentMode` slot core fills from `core.deployment.mode`, which it
	 * reads either way). Unless `mailSenderModules` is given, it also chooses
	 * the mail sender: `development` installs the one that logs each code, any
	 * other name the SMTP one, and none is installed when it is omitted. The
	 * MFA module reads it too, for the development sample key's refusal.
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
	/**
	 * The deployment's own modules behind core's `mailSender` slot. Given, they
	 * are installed under every environment name in place of the bundled
	 * sender, which is never installed beside them (a second provider would be
	 * a boot-time slot collision); an empty list installs no sender, and a
	 * module that needs one (the MFA email factor, or the MFA module with
	 * `requireEmailProof = "always"`) then refuses the boot.
	 */
	readonly mailSenderModules?: readonly Module[];
}

/**
 * The access-token lifetime core's `reference.conf` ships on the deprecated
 * `oauth.accessToken.expiresIn`. Not a default — nothing mints with it — only
 * what an unmodified deployment carries there, so the deprecation line can tell
 * an operator's override from the shipped value. Pinned against the real file
 * by `access-token-lifetime-alias.test.mts`.
 */
const SHIPPED_ACCESS_TOKEN_EXPIRES_IN = 3600;

/** Whether `value` sets anything: a value, or a section with one somewhere under it. */
function setsAnything(value: unknown): boolean {
	if (value === undefined) return false;
	if (typeof value !== "object" || value === null || Array.isArray(value)) return true;
	return Object.values(value).some(setsAnything);
}

/**
 * Compose the standalone module list from phase one's `config`: the
 * composition root's `adapters`, which choose the adapter behind each slot,
 * and the switches core's reader parsed. Kept out of `app.mts` so a smoke
 * test can check the manifest (that disabling federation grants removes their
 * modules, say) without an HTTP server. The rules for editing the list
 * (order, one module per store slot, the federation types it bundles) are in
 * the template README, "Module Composition Order".
 */
export function buildModules(config: Switches, overrides: BuildModulesOverrides = {}): Module[] {
	const logger = overrides.logger ?? consoleLogger;
	const adapters = config.adapters;

	// Federation grants: a user's standing consent that a client may obtain
	// upstream tokens with no session behind the call. Off by default, and off
	// installs nothing: no store, no socket, no boot requirement. On, the routes
	// and the background registry the shutdown drains come as a pair; each store
	// follows its own selection (grants in Redis with acquisition in memory is
	// a supported single-replica shape); and the subject-revocation service is
	// installed, whose `federationGrantStore` edge makes "revoke everything this
	// subject holds" include the grants. Enabling it also states the deployment
	// has a consent page, a callback per connection and a user repository
	// covering each connection's registration; the routes module refuses at
	// boot what is missing, naming it. A setting still written at the section's
	// old path, `federationGrants`, installs the feature too, so that boot
	// refuses it naming the new path rather than reading the feature as off.
	const federationGrantsEnabled =
		config["federation-grants"]?.enabled === true || setsAnything(config.federationGrants);

	// MFA: the template's own switch, `mfaMode` (MFA_MODE). `off` installs
	// nothing of MFA; `optional` and `required` install what `mfaModulesFor`
	// lists, the configuration then expects `mfa`
	// (`expectedSessionRequirements`) and `mfa.mode` is written from the
	// switch (`resolveForBoot`).
	const mfaInstalled = config.mfaMode !== "off";

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
	// When ANY selection is `"redis"`, or the refresh-token family modules keep
	// the Redis store (the default), the shared `standaloneRedisClientsModule`
	// is added once, one ioredis socket per replica; memory-only deployments
	// open none.
	const usingRedisAnywhere =
		refreshTokenFamilyUsesRedis ||
		adapters.rateLimiter === "redis" ||
		adapters.attemptCounter === "redis" ||
		adapters.userSessionStores === "redis" ||
		adapters.codeRepository === "redis" ||
		adapters.accessTokenDenylist === "redis" ||
		adapters.replaySeenSet === "redis" ||
		adapters.consentStore === "redis" ||
		adapters.federationTokenStore === "redis" ||
		// Only while the feature is on: a selection left at "redis" for a
		// feature that is off must not open a socket.
		(federationGrantsEnabled &&
			(adapters.federationGrantStore === "redis" ||
				adapters.federationGrantIntentStore === "redis")) ||
		(mfaInstalled &&
			(adapters.mfaFactorStore === "redis" || adapters.mfaTransactionStore === "redis"));

	// The four user-session stores and the subject-level revocation pair
	// follow `adapters.userSessionStores`; the federation-token store is always
	// wired and follows its own selection below.
	const sessionStoresModules: Module[] =
		adapters.userSessionStores === "redis"
			? [redisSessionStoresModule]
			: overrides.storesModule
				? [overrides.storesModule]
				: [inMemorySessionStoresModule];

	const rateLimiterModules: Module[] =
		adapters.rateLimiter === "redis" ? [redisRateLimiterModule] : [memoryRateLimiterModule];

	// `memory` installs no counter: the login's attempt guard counts per
	// process, which `core.deployment.mode = "multi"` refuses.
	const attemptCounterModules: Module[] =
		adapters.attemptCounter === "redis" ? [redisAttemptCounterModule] : [];

	// Mutually exclusive: both modules provide the `codeRepository` slot, and
	// including both would be a boot-time slot collision.
	const codeRepositoryModules: Module[] =
		adapters.codeRepository === "redis"
			? [redisCodeRepositoryModule]
			: [inMemoryCodeRepositoryModule];

	// The RFC 7009 access-token denylist has no "none": `oauthModule` mounts
	// `/oauth/revoke` and reads the `accessTokenDenylist` slot, and core's boot
	// validator refuses a composition that reads the slot with nothing filling
	// it, since the endpoint would answer 200 while the token kept working. The
	// memory denylist is a dev convenience: it forks per replica, so
	// `core.deployment.mode = "multi"` refuses it by name. The template ships
	// `"redis"`.
	const accessTokenDenylistModules: Module[] =
		adapters.accessTokenDenylist === "redis"
			? [redisAccessTokenDenylistModule]
			: [memoryAccessTokenDenylistModule];

	// Opt-in: `"none"` (the default) wires nothing, and a client that is not
	// first-party is refused. Each module provides both slots the consent step
	// needs (the consent records and the requests parked while the page asks),
	// so the two cannot be wired apart. The memory one declares itself
	// replica-unsafe and `core.deployment.mode = "multi"` refuses it by name;
	// the Redis one shares both over the ioredis socket.
	const consentStoreModules: Module[] =
		adapters.consentStore === "redis"
			? [redisConsentStoreModule]
			: adapters.consentStore === "memory"
				? [memoryConsentStoreModule]
				: [];

	// The jti single-use record behind private_key_jwt client authentication.
	const replaySeenSetModules: Module[] =
		adapters.replaySeenSet === "redis" ? [redisReplaySeenSetModule] : [memoryReplaySeenSetModule];

	// One federation-token-store module per adapter, so the memory one can
	// declare `replicaSafety` on its manifest and the Redis one can `require`
	// its client slot. The Redis module is built for this composition root so
	// its plaintext guard knows which environment selected the config; it
	// reads the replica count from core's `deploymentMode` slot.
	const federationTokenStoreModules: Module[] =
		adapters.federationTokenStore === "redis"
			? [redisFederationTokenStoreModuleFor({ environment: overrides.environment })]
			: [inMemoryFederationTokenStoreModule];

	// One module per store, nothing while the feature is off or the store is
	// `"none"` (the default), which the routes module refuses at boot naming
	// the store. The Redis grant store is built for this composition root so
	// its plaintext guard knows which environment selected the config, as the
	// federation-token store's is. Both memory modules declare
	// `replicaSafety`, so `core.deployment.mode = "multi"` refuses them by name;
	// the routes module itself refuses a Redis grant store beside memory
	// user-session stores, because the grants would outlive the boundary that
	// ends them.
	const federationGrantStoreModules: Module[] = !federationGrantsEnabled
		? []
		: adapters.federationGrantStore === "redis"
			? [
					overrides.environment === undefined
						? redisFederationGrantStoreModuleFor()
						: redisFederationGrantStoreModuleFor({ environment: overrides.environment }),
				]
			: adapters.federationGrantStore === "memory"
				? [memoryFederationGrantStoreModule]
				: [];
	const federationGrantIntentStoreModules: Module[] = !federationGrantsEnabled
		? []
		: adapters.federationGrantIntentStore === "redis"
			? [redisFederationGrantIntentStoreModule]
			: adapters.federationGrantIntentStore === "memory"
				? [memoryFederationGrantIntentStoreModule]
				: [];

	// What the MFA switch installs (`mfaSwitch.mts`): nothing while it is off.
	const mfaInstalledModules = mfaModulesFor({
		mode: config.mfaMode,
		adapters,
		storeTransport: config.storeTransport,
		environment: overrides.environment,
	});

	// The mail sender behind core's `mailSender` slot: the deployment's own when
	// given, otherwise the bundled one for the environment. The development one
	// logs each code and refuses the boot where the configuration or NODE_ENV
	// is production or staging, or the deployment multi-replica.
	const mailSenderModules: readonly Module[] =
		overrides.mailSenderModules ??
		(overrides.environment === undefined
			? []
			: overrides.environment === "development"
				? [standardDevelopmentMailSenderModule({ environment: overrides.environment })]
				: [standardSmtpMailSenderModule]);

	return [
		// MUST stay first: it declares no `before`/`after`, so this position is
		// what mounts express-session ahead of every session-consuming module.
		// Built from `config` so that `session-store.storage.type = "memory"` declares
		// itself replica-unsafe and `core.deployment.mode = "multi"` refuses it.
		sessionStoreModuleFor(config),
		// Under `/oauth` beside `oauthModule`, each parsing its own requests, so
		// their relative order does not matter; the browser half orders itself
		// after the session middleware by its own `after`.
		...(federationGrantsEnabled ? federationGrantsModules : []),
		oauthModule({ config }),
		oauthSessionGrantModule,
		oauthAuthorizationModule({ config }),
		// Always wired: a provider that signs tokens must publish its
		// verification keys regardless of OIDC issuer config, and `oauthModule`'s
		// discovery `jwks_uri` (advertised when an issuer is set) must resolve.
		jwksModule,
		sessionModule,
		// The federation types the template bundles, always: each contributes
		// its type, and boot hands it every enabled `core.federations` entry
		// that names it, under the entry's name. Nothing here reads an entry.
		googleFederationTypeModule(),
		oidcFederationTypeModule(),
		// The template's own settings: `logging {}` and `http {}`.
		loggingModule,
		httpModule,
		overrides.keyStoreModule ?? keyStoreModule,
		overrides.repositoriesModule ??
			repositoriesModuleFor({ client: adapters.clientRepository, user: adapters.userRepository }),
		// The audit sink, always wired: `emitAuditEvent` no-ops on an empty slot,
		// so the routes' security events (`token.issued.failure`,
		// `authorize.rejected`, `rate_limit.unavailable`, …) would go nowhere.
		// Which sink is a selection (`adapters.auditSink`); whether there is one
		// is not.
		overrides.auditSinkModule ?? auditSinkModuleFor(adapters.auditSink),
		...mailSenderModules,
		...(usingRedisAnywhere ? [standaloneRedisClientsModule] : []),
		...federationTokenStoreModules,
		...federationGrantStoreModules,
		...federationGrantIntentStoreModules,
		...sessionStoresModules,
		...rateLimiterModules,
		...attemptCounterModules,
		...codeRepositoryModules,
		...accessTokenDenylistModules,
		...replaySeenSetModules,
		...consentStoreModules,
		...refreshTokenFamilyModules,
		defaultRefreshTokenFamilyRotationModule,
		defaultRefreshTokenFamilyRevocationModule,
		// MFA's modules and stores; the MFA routes order themselves after the
		// session middleware.
		...mfaInstalledModules,
		// The composed "end everything this subject holds" a credential change
		// calls, reached as `handle.components.subjectRevocationService`.
		// Installed with federation grants, which is what makes it reach the
		// grants, and with MFA, whose operator reset ends every session and
		// token of the subject's through it; otherwise a Store calls core's
		// revokeAllForSubject.
		...(federationGrantsEnabled || mfaInstalled ? [subjectRevocationServiceModule] : []),
	];
}
