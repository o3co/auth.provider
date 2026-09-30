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

/**
 * The stores' sections, the federation-grants section and the WebAuthn
 * variables, through the template's own reading of the full set: the
 * operator's layer and environment read once, phase one's switches, then the
 * layers over every loaded package's `reference.conf` handed to boot. Each
 * section is read at its module's name and refuses a key it does not declare;
 * a path it moved from refuses boot naming the new one; a variable renamed
 * with the move refuses boot unless its new name carries the same value.
 */

import { BootError, type RateLimiter } from "@o3co/auth-provider-core";
import {
	MULTI_ENV,
	SINGLE_ENV,
} from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { testRedis } from "../../../../packages/redis/__tests__/support/redis.mts";
import { composeFullSet, type FullSet, type FullSetOptions } from "./full-set.fixture.mts";

let current: FullSet | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

/** Boots the full set, the operator's layer and environment as given, and remembers it. */
async function boot(options: FullSetOptions = {}): Promise<FullSet> {
	current = await composeFullSet(options);
	return current;
}

/** What boot refused the full set with. */
async function refused(options: FullSetOptions): Promise<BootError> {
	try {
		current = await composeFullSet(options);
	} catch (err) {
		if (err instanceof BootError) return err;
		throw err;
	}
	throw new Error("the full set booted");
}

/** A section the parsed configuration holds, by its top-level name. */
const sectionOf = (composition: FullSet, name: string): unknown =>
	(composition.config as unknown as Record<string, unknown>)[name];

/** The full set's multi-replica environment, on this file's Redis database. */
let redisEnv: Readonly<Record<string, string>>;

beforeAll(async () => {
	const redis = await testRedis();
	const url = `redis://${redis.host}:${redis.port}/${redis.db}`;
	redisEnv = {
		...MULTI_ENV,
		REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: url,
		SESSION_STORAGE_REDIS_URL: url,
	};
});

/** The full set with every store on Redis, the refresh-token family store included. */
const onRedis = (options: FullSetOptions = {}): FullSetOptions => ({
	stores: "redis",
	shippedRefreshTokenFamilyStore: true,
	...options,
	env: { ...redisEnv, ...options.env },
});

/** Every key written at an old path, refused as moved: `{ module, from, to, environmentVariable? }` each. */
async function relocatedBy(options: FullSetOptions): Promise<unknown> {
	const err = await refused(options);
	expect(err.reason).toBe("config-path-relocated");
	return (err.details as { relocated: unknown }).relocated;
}

describe("each store's section read at its module's name, through the template's reading", () => {
	it("the in-process stores: their caps and the limiter's budgets and bucket bound", async () => {
		const composition = await boot({
			env: { ...SINGLE_ENV, CORE_RATE_LIMITER_MEMORY_MAX_BUCKETS: "500" },
			operatorHocon: [
				"core-rate-limiter-memory.limits.token { limit = 7, windowSeconds = 60 }",
				"core-replay-seen-set-memory.maxEntries = 5001",
				"core-challenge-store-memory.maxEntries = 5002",
				"core-mfa-transaction-store-memory.maxEntries = 5003",
				"",
			].join("\n"),
		});

		expect(sectionOf(composition, "core-rate-limiter-memory")).toEqual({
			limits: { token: { limit: 7, windowSeconds: 60 } },
			defaultLimit: { limit: 60, windowSeconds: 60 },
			maxBuckets: 500,
		});
		const components = composition.handle.components as unknown as Record<
			string,
			{ maxEntries?: number }
		>;
		expect(components.replaySeenSet?.maxEntries).toBe(5001);
		expect(components.challengeStore?.maxEntries).toBe(5002);
		expect(components.mfaTransactionStore?.maxEntries).toBe(5003);
		const limiter = composition.handle.components.rateLimiter as RateLimiter;
		expect((await limiter.check("token:ip:192.0.2.1", { ip: "192.0.2.1" })).limit).toBe(7);
	});

	it("the Redis stores: each prefix and setting at its own section, the limiter's outage policy among them", async () => {
		const composition = await boot(
			onRedis({
				operatorHocon: [
					'redis-access-token-denylist.keyPrefix = "t1:atdeny:"',
					'redis-challenge-store.keyPrefix = "t1:chal:"',
					'redis-consent-store.keyPrefix = "t1:consent:"',
					'redis-device-code-store.keyPrefix = "t1:devauth:"',
					'redis-mfa-factor-store.keyPrefix = "t1:mfaf:"',
					'redis-mfa-transaction-store.keyPrefix = "t1:mfat:"',
					'redis-rate-limiter { failMode = "open", limits.token { limit = 9, windowSeconds = 60 } }',
					'redis-refresh-token-family-store { keyPrefix = "t1:rtfam:", casRetryLimit = 5 }',
					'redis-replay-seen-set.keyPrefix = "t1:replay:"',
					'redis-session-stores.keyPrefix = "t1:ss:"',
					'redis-federation-token-store { keyPrefix = "t1:ft:", ttl = 172800 }',
					"",
				].join("\n"),
			}),
		);

		for (const [name, prefix] of [
			["redis-access-token-denylist", "t1:atdeny:"],
			["redis-challenge-store", "t1:chal:"],
			["redis-consent-store", "t1:consent:"],
			["redis-device-code-store", "t1:devauth:"],
			["redis-mfa-factor-store", "t1:mfaf:"],
			["redis-mfa-transaction-store", "t1:mfat:"],
			["redis-refresh-token-family-store", "t1:rtfam:"],
			["redis-replay-seen-set", "t1:replay:"],
			["redis-session-stores", "t1:ss:"],
			["redis-federation-token-store", "t1:ft:"],
		] as const) {
			expect((sectionOf(composition, name) as { keyPrefix: unknown }).keyPrefix, name).toBe(prefix);
		}
		expect(sectionOf(composition, "redis-refresh-token-family-store")).toMatchObject({
			casRetryLimit: 5,
		});
		expect(sectionOf(composition, "redis-federation-token-store")).toMatchObject({ ttl: 172800 });
		const limiter = composition.handle.components.rateLimiter as RateLimiter;
		expect(limiter.failMode).toBe("open");
		expect((await limiter.check("token:ip:192.0.2.1", { ip: "192.0.2.1" })).limit).toBe(9);
	});
});

describe("a path a store's section moved from, written in the operator's own layer", () => {
	const unbound = (module: string, from: string, to: string) => ({ module, from, to });
	const bound = (module: string, from: string, to: string, environmentVariable: string) => ({
		module,
		from,
		to,
		environmentVariable,
	});

	it("the in-process stores: each key refused, naming its path under the module's section", async () => {
		const relocated = await relocatedBy({
			operatorHocon: [
				"memoryRateLimiter {",
				"  maxBuckets = 500",
				"  defaultLimit { limit = 5, windowSeconds = 60 }",
				"  limits.token { limit = 7, windowSeconds = 60 }",
				"}",
				"replaySeenSet.memory.maxEntries = 5001",
				"challengeStore.memory.maxEntries = 5002",
				"mfaTransactionStore.memory.maxEntries = 5003",
				"",
			].join("\n"),
		});

		expect(relocated).toHaveLength(8);
		expect(relocated).toEqual(
			expect.arrayContaining([
				bound(
					"core-rate-limiter-memory",
					"memoryRateLimiter.maxBuckets",
					"core-rate-limiter-memory.maxBuckets",
					"CORE_RATE_LIMITER_MEMORY_MAX_BUCKETS",
				),
				unbound(
					"core-rate-limiter-memory",
					"memoryRateLimiter.defaultLimit.limit",
					"core-rate-limiter-memory.defaultLimit.limit",
				),
				unbound(
					"core-rate-limiter-memory",
					"memoryRateLimiter.defaultLimit.windowSeconds",
					"core-rate-limiter-memory.defaultLimit.windowSeconds",
				),
				unbound(
					"core-rate-limiter-memory",
					"memoryRateLimiter.limits.token.limit",
					"core-rate-limiter-memory.limits.token.limit",
				),
				unbound(
					"core-rate-limiter-memory",
					"memoryRateLimiter.limits.token.windowSeconds",
					"core-rate-limiter-memory.limits.token.windowSeconds",
				),
				unbound(
					"core-replay-seen-set-memory",
					"replaySeenSet.memory.maxEntries",
					"core-replay-seen-set-memory.maxEntries",
				),
				unbound(
					"core-challenge-store-memory",
					"challengeStore.memory.maxEntries",
					"core-challenge-store-memory.maxEntries",
				),
				unbound(
					"core-mfa-transaction-store-memory",
					"mfaTransactionStore.memory.maxEntries",
					"core-mfa-transaction-store-memory.maxEntries",
				),
			]),
		);
	});

	it("the Redis stores: each key refused, naming its path under the module's section and the variable bound there", async () => {
		const relocated = await relocatedBy(
			onRedis({
				operatorHocon: [
					'redisAccessTokenDenylist.keyPrefix = "t1:atdeny:"',
					'redisChallengeStore.keyPrefix = "t1:chal:"',
					'redisConsentStore.keyPrefix = "t1:consent:"',
					'redisDeviceCodeStore.keyPrefix = "t1:devauth:"',
					'redisMfaFactorStore.keyPrefix = "t1:mfaf:"',
					'redisMfaTransactionStore.keyPrefix = "t1:mfat:"',
					"redisRateLimiter.defaultLimit { limit = 5, windowSeconds = 60 }",
					'rateLimit.failMode = "open"',
					'redisRefreshTokenFamilyStore { keyPrefix = "t1:rtfam:", casRetryLimit = 5 }',
					'redisReplaySeenSet.keyPrefix = "t1:replay:"',
					'redisSessionStores.keyPrefix = "t1:ss:"',
					"redisFederationTokenStore {",
					'  keyPrefix = "t1:ft:"',
					"  ttl = 172800",
					'  encryptionMode = "required"',
					'  encryptionKey = "not-a-key"',
					"  scanFallback = false",
					"}",
					"",
				].join("\n"),
			}),
		);

		expect(relocated).toHaveLength(18);
		expect(relocated).toEqual(
			expect.arrayContaining([
				bound(
					"redis-access-token-denylist",
					"redisAccessTokenDenylist.keyPrefix",
					"redis-access-token-denylist.keyPrefix",
					"REDIS_ACCESS_TOKEN_DENYLIST_KEY_PREFIX",
				),
				unbound(
					"redis-challenge-store",
					"redisChallengeStore.keyPrefix",
					"redis-challenge-store.keyPrefix",
				),
				bound(
					"redis-consent-store",
					"redisConsentStore.keyPrefix",
					"redis-consent-store.keyPrefix",
					"REDIS_CONSENT_STORE_KEY_PREFIX",
				),
				unbound(
					"redis-device-code-store",
					"redisDeviceCodeStore.keyPrefix",
					"redis-device-code-store.keyPrefix",
				),
				bound(
					"redis-mfa-factor-store",
					"redisMfaFactorStore.keyPrefix",
					"redis-mfa-factor-store.keyPrefix",
					"REDIS_MFA_FACTOR_STORE_KEY_PREFIX",
				),
				bound(
					"redis-mfa-transaction-store",
					"redisMfaTransactionStore.keyPrefix",
					"redis-mfa-transaction-store.keyPrefix",
					"REDIS_MFA_TRANSACTION_STORE_KEY_PREFIX",
				),
				unbound(
					"redis-rate-limiter",
					"redisRateLimiter.defaultLimit.limit",
					"redis-rate-limiter.defaultLimit.limit",
				),
				unbound(
					"redis-rate-limiter",
					"redisRateLimiter.defaultLimit.windowSeconds",
					"redis-rate-limiter.defaultLimit.windowSeconds",
				),
				bound(
					"redis-rate-limiter",
					"rateLimit.failMode",
					"redis-rate-limiter.failMode",
					"REDIS_RATE_LIMITER_FAIL_MODE",
				),
				bound(
					"redis-refresh-token-family-store",
					"redisRefreshTokenFamilyStore.keyPrefix",
					"redis-refresh-token-family-store.keyPrefix",
					"REDIS_REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX",
				),
				bound(
					"redis-refresh-token-family-store",
					"redisRefreshTokenFamilyStore.casRetryLimit",
					"redis-refresh-token-family-store.casRetryLimit",
					"REDIS_REFRESH_TOKEN_FAMILY_STORE_CAS_RETRY_LIMIT",
				),
				unbound(
					"redis-replay-seen-set",
					"redisReplaySeenSet.keyPrefix",
					"redis-replay-seen-set.keyPrefix",
				),
				bound(
					"redis-session-stores",
					"redisSessionStores.keyPrefix",
					"redis-session-stores.keyPrefix",
					"REDIS_SESSION_STORES_KEY_PREFIX",
				),
				bound(
					"redis-federation-token-store",
					"redisFederationTokenStore.keyPrefix",
					"redis-federation-token-store.keyPrefix",
					"REDIS_FEDERATION_TOKEN_STORE_KEY_PREFIX",
				),
				unbound(
					"redis-federation-token-store",
					"redisFederationTokenStore.ttl",
					"redis-federation-token-store.ttl",
				),
				bound(
					"redis-federation-token-store",
					"redisFederationTokenStore.encryptionMode",
					"redis-federation-token-store.encryptionMode",
					"REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_MODE",
				),
				bound(
					"redis-federation-token-store",
					"redisFederationTokenStore.encryptionKey",
					"redis-federation-token-store.encryptionKey",
					"REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY",
				),
				unbound(
					"redis-federation-token-store",
					"redisFederationTokenStore.scanFallback",
					"redis-federation-token-store.scanFallback",
				),
			]),
		);
		expect(JSON.stringify(relocated)).not.toContain("not-a-key");
	});
});

describe("federation grants read at their modules' names, through the template's reading", () => {
	it("the federation-grants module's section, and the in-process grant store's retention", async () => {
		const composition = await boot({
			operatorHocon: [
				"federation-grants { maxExpiresIn = 86400, defaultExpiresIn = 3600 }",
				"core-federation-grant-store-memory.tombstoneRetention = 600",
				"",
			].join("\n"),
		});

		expect(sectionOf(composition, "federation-grants")).toMatchObject({
			enabled: true,
			maxExpiresIn: 86400,
			defaultExpiresIn: 3600,
			consent: { url: "/consent/grants" },
		});
		expect(sectionOf(composition, "core-federation-grant-store-memory")).toEqual({
			tombstoneRetention: 600,
		});
	});

	it("phase one chooses the feature's modules by federation-grants.enabled", async () => {
		const { FEDERATION_GRANTS_ENABLED: _enabled, ...unset } = SINGLE_ENV;
		const on = await boot({ env: unset, operatorHocon: "federation-grants.enabled = true\n" });
		expect(on.modules.map((module) => module.name)).toContain("federation-grants");
		await on.handle.dispose();
		current = undefined;

		const off = await boot({ env: unset });
		expect(off.modules.map((module) => module.name)).not.toContain("federation-grants");
	});

	it("the Redis grant stores: each its own prefix, the grant store its key ring, retention and listing allowance", async () => {
		const composition = await boot(
			onRedis({
				operatorHocon: [
					'redis-federation-grant-store { keyPrefix = "t1:fg:", listingAllowanceMs = 1000, tombstoneRetention = 60 }',
					'redis-federation-grant-intent-store.keyPrefix = "t1:fgi:"',
					"",
				].join("\n"),
			}),
		);

		const grants = sectionOf(composition, "redis-federation-grant-store") as {
			encryptionKeys?: unknown[];
		};
		expect(grants).toMatchObject({
			keyPrefix: "t1:fg:",
			listingAllowanceMs: 1000,
			tombstoneRetention: 60,
			encryptionMode: "required",
		});
		expect(grants.encryptionKeys).toHaveLength(1);
		expect(sectionOf(composition, "redis-federation-grant-intent-store")).toEqual({
			keyPrefix: "t1:fgi:",
		});
	});
});

describe("the Redis grant store's key prefix moved and the intent store's left at its default", () => {
	const GRANT = "REDIS_FEDERATION_GRANT_STORE_KEY_PREFIX";
	const INTENT = "REDIS_FEDERATION_GRANT_INTENT_STORE_KEY_PREFIX";

	it("refuses boot, naming both keys and both variables and quoting no value", async () => {
		const err = await composeFullSet(onRedis({ env: { [GRANT]: "t1:fg:" } })).then(
			async (composition) => {
				await composition.handle.dispose();
				throw new Error("the full set booted");
			},
			(error: unknown) => error,
		);
		expect(err).toBeInstanceOf(RangeError);
		const { message } = err as RangeError;
		expect(message).toContain(`redis-federation-grant-store.keyPrefix (${GRANT})`);
		expect(message).toContain(`redis-federation-grant-intent-store.keyPrefix (${INTENT})`);
		expect(message).not.toContain("fg:");
	});

	it.each([
		["both set to the same prefix", { [GRANT]: "t1:fg:", [INTENT]: "t1:fg:" }],
		["each set to a prefix of its own", { [GRANT]: "t1:fg:", [INTENT]: "t1:fgi:" }],
		["neither set", {}],
	])("boots with %s", async (_, env: Readonly<Record<string, string>>) => {
		const composition = await boot(onRedis({ env }));
		expect(sectionOf(composition, "redis-federation-grant-store")).toMatchObject({
			keyPrefix: env[GRANT] ?? "fg:",
		});
		expect(sectionOf(composition, "redis-federation-grant-intent-store")).toEqual({
			keyPrefix: env[INTENT] ?? "fg:",
		});
	});
});

describe("a path the federation-grants sections moved from, written in the operator's own layer", () => {
	const unbound = (module: string, from: string, to: string) => ({ module, from, to });
	const bound = (module: string, from: string, to: string, environmentVariable: string) => ({
		module,
		from,
		to,
		environmentVariable,
	});

	it("federationGrants: each key refused, naming its path under federation-grants, the in-process store's retention under its own section", async () => {
		const relocated = await relocatedBy({
			operatorHocon: [
				"federationGrants {",
				"  enabled = true",
				"  maxExpiresIn = 86400",
				"  allowKeepOnSubjectRevocation = false",
				'  identityLookup = "unsupported"',
				'  consent.url = "/consent/old"',
				"  tombstoneRetention = 600",
				'  connections.old { federation = "oidc", scopes = ["openid"], boundary = "b", maxAccessTokenLifetime = 60 }',
				"}",
				"",
			].join("\n"),
		});

		const grants = "federation-grants";
		expect(relocated).toHaveLength(10);
		expect(relocated).toEqual(
			expect.arrayContaining([
				bound(grants, "federationGrants.enabled", `${grants}.enabled`, "FEDERATION_GRANTS_ENABLED"),
				unbound(grants, "federationGrants.maxExpiresIn", `${grants}.maxExpiresIn`),
				bound(
					grants,
					"federationGrants.allowKeepOnSubjectRevocation",
					`${grants}.allowKeepOnSubjectRevocation`,
					"FEDERATION_GRANTS_ALLOW_KEEP_ON_SUBJECT_REVOCATION",
				),
				bound(
					grants,
					"federationGrants.identityLookup",
					`${grants}.identityLookup`,
					"FEDERATION_GRANTS_IDENTITY_LOOKUP",
				),
				bound(
					grants,
					"federationGrants.consent.url",
					`${grants}.consent.url`,
					"FEDERATION_GRANTS_CONSENT_URL",
				),
				unbound(
					"core-federation-grant-store-memory",
					"federationGrants.tombstoneRetention",
					"core-federation-grant-store-memory.tombstoneRetention",
				),
				unbound(
					grants,
					"federationGrants.connections.old.federation",
					`${grants}.connections.old.federation`,
				),
				unbound(
					grants,
					"federationGrants.connections.old.scopes",
					`${grants}.connections.old.scopes`,
				),
				unbound(
					grants,
					"federationGrants.connections.old.boundary",
					`${grants}.connections.old.boundary`,
				),
				unbound(
					grants,
					"federationGrants.connections.old.maxAccessTokenLifetime",
					`${grants}.connections.old.maxAccessTokenLifetime`,
				),
			]),
		);
	});

	it("federationGrants.enabled alone, with the variable unset: refused, not read as off", async () => {
		const { FEDERATION_GRANTS_ENABLED: _enabled, ...unset } = SINGLE_ENV;
		const relocated = await relocatedBy({
			env: unset,
			operatorHocon: "federationGrants.enabled = true\n",
		});

		expect(relocated).toEqual([
			bound(
				"federation-grants",
				"federationGrants.enabled",
				"federation-grants.enabled",
				"FEDERATION_GRANTS_ENABLED",
			),
		]);
	});

	it("the Redis grant store's keys, under federationGrants and redisFederationGrantStore: refused, naming its own section", async () => {
		const relocated = await relocatedBy(
			onRedis({
				operatorHocon: [
					"federationGrants {",
					'  encryptionMode = "required"',
					'  encryptionKeys = [{ id = "k-old", key = "not-a-key" }]',
					"  tombstoneRetention = 60",
					"}",
					'redisFederationGrantStore { keyPrefix = "t1:fg:", listingAllowanceMs = 1000 }',
					"",
				].join("\n"),
			}),
		);

		const store = "redis-federation-grant-store";
		expect(relocated).toHaveLength(6);
		expect(relocated).toEqual(
			expect.arrayContaining([
				bound(
					store,
					"federationGrants.encryptionMode",
					`${store}.encryptionMode`,
					"REDIS_FEDERATION_GRANT_STORE_ENCRYPTION_MODE",
				),
				unbound(store, "federationGrants.encryptionKeys.0.id", `${store}.encryptionKeys.0.id`),
				unbound(store, "federationGrants.encryptionKeys.0.key", `${store}.encryptionKeys.0.key`),
				unbound(store, "federationGrants.tombstoneRetention", `${store}.tombstoneRetention`),
				bound(
					store,
					"redisFederationGrantStore.keyPrefix",
					`${store}.keyPrefix`,
					"REDIS_FEDERATION_GRANT_STORE_KEY_PREFIX",
				),
				unbound(
					store,
					"redisFederationGrantStore.listingAllowanceMs",
					`${store}.listingAllowanceMs`,
				),
			]),
		);
		expect(JSON.stringify(relocated)).not.toContain("not-a-key");
	});
});

describe("a key a store's section does not declare", () => {
	it.each([
		["core-rate-limiter-memory.maxBucket = 5", "maxBucket", false],
		[
			"core-rate-limiter-memory.limits.token { limit = 5, windowSeconds = 60, window = 1 }",
			"window",
			false,
		],
		["core-replay-seen-set-memory.maxEntry = 5", "maxEntry", false],
		['redis-consent-store.prefix = "x:"', "prefix", true],
		['redis-rate-limiter.failmode = "open"', "failmode", true],
		["redis-refresh-token-family-store.casRetries = 2", "casRetries", true],
		['redis-federation-token-store.encryptionKeys = ["x"]', "encryptionKeys", true],
		['redis-session-stores.keyPrefixes = "x:"', "keyPrefixes", true],
		["federation-grants.maxExpiresInn = 5", "maxExpiresInn", false],
		['federation-grants.connections.calendar.scope = ["openid"]', "scope", false],
		["core-federation-grant-store-memory.tombstone = 1", "tombstone", false],
		['redis-federation-grant-store.keyPrefixes = "x:"', "keyPrefixes", true],
		['redis-federation-grant-intent-store.prefix = "x:"', "prefix", true],
	])("%s: refused, naming %s", async (hocon, key, redis) => {
		const options = redis ? onRedis() : {};
		const err = await refused({ ...options, operatorHocon: `${hocon}\n` });

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain(`"${key}"`);
	});
});

describe("a store variable renamed with the move, through the template's reading", () => {
	/** Each renamed variable: its old name, its new name, its module, the path the new one binds, a value, and the boot it needs. */
	const ROWS = [
		{
			from: "MEMORY_RATE_LIMITER_MAX_BUCKETS",
			to: "CORE_RATE_LIMITER_MEMORY_MAX_BUCKETS",
			module: "core-rate-limiter-memory",
			path: "core-rate-limiter-memory.maxBuckets",
			value: "500",
			options: (): FullSetOptions => ({ env: SINGLE_ENV }),
		},
		{
			from: "RATE_LIMIT_FAIL_MODE",
			to: "REDIS_RATE_LIMITER_FAIL_MODE",
			module: "redis-rate-limiter",
			path: "redis-rate-limiter.failMode",
			value: "open",
			options: (): FullSetOptions => onRedis(),
		},
		{
			from: "REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX",
			to: "REDIS_REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX",
			module: "redis-refresh-token-family-store",
			path: "redis-refresh-token-family-store.keyPrefix",
			value: "t1:rtfam:",
			options: (): FullSetOptions => onRedis(),
		},
		{
			from: "FEDERATION_GRANTS_ENCRYPTION_MODE",
			to: "REDIS_FEDERATION_GRANT_STORE_ENCRYPTION_MODE",
			module: "redis-federation-grant-store",
			path: "redis-federation-grant-store.encryptionMode",
			value: "required",
			options: (): FullSetOptions => onRedis(),
		},
		{
			from: "REFRESH_TOKEN_FAMILY_STORE_CAS_RETRY_LIMIT",
			to: "REDIS_REFRESH_TOKEN_FAMILY_STORE_CAS_RETRY_LIMIT",
			module: "redis-refresh-token-family-store",
			path: "redis-refresh-token-family-store.casRetryLimit",
			value: "5",
			options: (): FullSetOptions => onRedis(),
		},
	] as const;

	/** `options()` with `set` laid over its environment. */
	const withEnv = (options: FullSetOptions, set: Record<string, string>): FullSetOptions => ({
		...options,
		env: { ...options.env, ...set },
	});

	it.each(ROWS)(
		"$from set alone: refused, naming $to and $path",
		async ({ from, to, module, path, value, options }) => {
			const err = await refused(withEnv(options(), { [from]: value }));

			expect(err.details).toEqual({
				reason: "environment-variable-renamed",
				renamed: [{ module, from, to, path, state: "unset" }],
			});
		},
	);

	it.each(ROWS)(
		"$from set beside $to at a different value: refused, naming neither value",
		async ({ from, to, options }) => {
			const err = await refused(withEnv(options(), { [from]: "old-5e2d", [to]: "new-c81a" }));

			expect(err.details).toMatchObject({ renamed: [{ from, to, state: "different" }] });
			for (const value of ["old-5e2d", "new-c81a"]) {
				expect(err.message).not.toContain(value);
				expect(JSON.stringify(err.details)).not.toContain(value);
			}
		},
	);

	it.each(ROWS)(
		"$from set beside $to at the same value: boots, the value at $path",
		async ({ from, to, path, value, options }) => {
			const composition = await boot(withEnv(options(), { [from]: value, [to]: value }));

			const [section, key] = path.split(".") as [string, string];
			expect(String((sectionOf(composition, section) as Record<string, unknown>)[key])).toBe(value);
		},
	);
});

describe("a WebAuthn rate-limit variable renamed to the name its path derives, through the template's reading", () => {
	/** Each renamed variable: its old name, its new name, the path the new one binds, a value. */
	const ROWS = [
		{
			from: "WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT",
			to: "WEBAUTHN_RATE_LIMIT_AUTHENTICATION_OPTIONS_LIMIT",
			path: "webauthn.rateLimit.authenticationOptions.limit",
			value: "12",
		},
		{
			from: "WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_WINDOW_SECONDS",
			to: "WEBAUTHN_RATE_LIMIT_AUTHENTICATION_OPTIONS_WINDOW_SECONDS",
			path: "webauthn.rateLimit.authenticationOptions.windowSeconds",
			value: "120",
		},
	] as const;

	it.each(ROWS)(
		"$from set alone: refused, naming $to and $path",
		async ({ from, to, path, value }) => {
			const err = await refused({ env: { ...SINGLE_ENV, [from]: value } });

			expect(err.details).toEqual({
				reason: "environment-variable-renamed",
				renamed: [{ module: "webauthn", from, to, path, state: "unset" }],
			});
		},
	);

	it.each(ROWS)(
		"$from set beside $to at a different value: refused, naming neither value",
		async ({ from, to }) => {
			const err = await refused({ env: { ...SINGLE_ENV, [from]: "31", [to]: "47" } });

			expect(err.details).toMatchObject({ renamed: [{ from, to, state: "different" }] });
			for (const value of ["31", "47"]) {
				expect(JSON.stringify(err.details)).not.toContain(`"${value}"`);
			}
		},
	);

	it.each(ROWS)(
		"$from set beside $to at the same value: boots, the value at $path",
		async ({ from, to, path, value }) => {
			const composition = await boot({ env: { ...SINGLE_ENV, [from]: value, [to]: value } });

			const key = path.split(".").at(-1) as string;
			const options = (
				sectionOf(composition, "webauthn") as {
					rateLimit: { authenticationOptions: Record<string, unknown> };
				}
			).rateLimit.authenticationOptions;
			expect(String(options[key])).toBe(value);
		},
	);
});
