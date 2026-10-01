/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * The package's `config/reference.conf`: every store module that reads
 * configuration is read at the section named after it, declares this file as
 * its section's reference, and the file holds only those sections, which
 * their schemas parse without losing a path — core's
 * `packageReferenceProblems`, the check every package with defaults runs over
 * its own file. Each variable is named after the path it sets; the renamed
 * ones are declared, their old names bound nowhere but their captures.
 */

import { fileURLToPath } from "node:url";
import type { Module } from "@o3co/auth-provider-core";
import { packageReferenceProblems } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import {
	redisAccessTokenDenylistModule,
	redisChallengeStoreModule,
	redisCodeRepositoryModule,
	redisConsentStoreModule,
	redisDeviceCodeStoreModule,
	redisFederationGrantIntentStoreModule,
	redisFederationGrantStoreModule,
	redisFederationTokenStoreModule,
	redisMfaFactorStoreModule,
	redisMfaTransactionStoreModule,
	redisRateLimiterModule,
	redisRefreshTokenFamilyStoreModule,
	redisReplaySeenSetModule,
	redisSessionStoresModule,
} from "#/index.mjs";

/** The package's defaults, as a composition root finds them. */
const REFERENCE = new URL("../config/reference.conf", import.meta.url);

const MODULES: readonly Module[] = [
	redisAccessTokenDenylistModule,
	redisChallengeStoreModule,
	redisCodeRepositoryModule,
	redisConsentStoreModule,
	redisDeviceCodeStoreModule,
	redisFederationGrantIntentStoreModule,
	redisFederationGrantStoreModule,
	redisFederationTokenStoreModule,
	redisMfaFactorStoreModule,
	redisMfaTransactionStoreModule,
	redisRateLimiterModule,
	redisRefreshTokenFamilyStoreModule,
	redisReplaySeenSetModule,
	redisSessionStoresModule,
];

const read = (path: string, env: Readonly<Record<string, string>>): unknown =>
	parseFile(path, { env: { ...env } }).toObject();

/** The value the file resolves at `path` with `env` set. */
const resolvedAt = (path: string, env: Readonly<Record<string, string>> = {}): unknown =>
	path
		.split(".")
		.reduce<unknown>(
			(value, key) => (value as Record<string, unknown> | undefined)?.[key],
			read(fileURLToPath(REFERENCE), env),
		);

describe("the package's config/reference.conf", () => {
	it("is read at the section named after each store module that reads configuration", () => {
		expect(
			MODULES.map((module) => [module.name, module.section !== undefined, module.section?.at]),
		).toEqual(MODULES.map((module) => [module.name, true, undefined]));
	});

	it("is declared by each of them and holds only their sections, which their schemas parse without losing a path", () => {
		expect(packageReferenceProblems({ reference: REFERENCE, modules: MODULES, read })).toEqual([]);
	});

	it("declares the variables renamed with the move", () => {
		expect(redisRateLimiterModule.section?.renamedVariables).toEqual({
			RATE_LIMIT_FAIL_MODE: "rateLimit.failMode",
		});
		expect(redisRefreshTokenFamilyStoreModule.section?.renamedVariables).toEqual({
			REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX: "redisRefreshTokenFamilyStore.keyPrefix",
			REFRESH_TOKEN_FAMILY_STORE_CAS_RETRY_LIMIT: "redisRefreshTokenFamilyStore.casRetryLimit",
		});
		expect(redisFederationGrantStoreModule.section?.renamedVariables).toEqual({
			FEDERATION_GRANTS_ENCRYPTION_MODE: "federationGrants.encryptionMode",
		});
		expect(redisCodeRepositoryModule.section?.renamedVariables).toEqual({
			CLIENT_CODE_KEY_PREFIX: "redisCodeRepository.keyPrefix",
			CLIENT_CODE_DEFAULT_EXPIRES_IN: "redisCodeRepository.defaultExpiresIn",
			CLIENT_CODE_ENDPOINT_URI: "repositories.code.redis.endpointUri",
			CLIENT_CODE_PASSWORD: "repositories.code.redis.password",
		});
	});

	it.each([
		["REDIS_ACCESS_TOKEN_DENYLIST_KEY_PREFIX", "redis-access-token-denylist.keyPrefix"],
		["REDIS_CODE_REPOSITORY_KEY_PREFIX", "redis-code-repository.keyPrefix"],
		["REDIS_CODE_REPOSITORY_DEFAULT_EXPIRES_IN", "redis-code-repository.defaultExpiresIn"],
		["REDIS_CONSENT_STORE_KEY_PREFIX", "redis-consent-store.keyPrefix"],
		["REDIS_MFA_FACTOR_STORE_KEY_PREFIX", "redis-mfa-factor-store.keyPrefix"],
		["REDIS_MFA_TRANSACTION_STORE_KEY_PREFIX", "redis-mfa-transaction-store.keyPrefix"],
		["REDIS_RATE_LIMITER_FAIL_MODE", "redis-rate-limiter.failMode"],
		["REDIS_REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX", "redis-refresh-token-family-store.keyPrefix"],
		[
			"REDIS_REFRESH_TOKEN_FAMILY_STORE_CAS_RETRY_LIMIT",
			"redis-refresh-token-family-store.casRetryLimit",
		],
		["REDIS_SESSION_STORES_KEY_PREFIX", "redis-session-stores.keyPrefix"],
		["REDIS_FEDERATION_TOKEN_STORE_KEY_PREFIX", "redis-federation-token-store.keyPrefix"],
		["REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_MODE", "redis-federation-token-store.encryptionMode"],
		["REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY", "redis-federation-token-store.encryptionKey"],
		["REDIS_FEDERATION_GRANT_STORE_KEY_PREFIX", "redis-federation-grant-store.keyPrefix"],
		["REDIS_FEDERATION_GRANT_STORE_ENCRYPTION_MODE", "redis-federation-grant-store.encryptionMode"],
		[
			"REDIS_FEDERATION_GRANT_INTENT_STORE_KEY_PREFIX",
			"redis-federation-grant-intent-store.keyPrefix",
		],
	])("binds %s at %s", (variable, path) => {
		expect(resolvedAt(path, { [variable]: "__set__" })).toBe("__set__");
	});

	it.each([
		["redis-access-token-denylist.keyPrefix", "atdeny:"],
		["redis-challenge-store.keyPrefix", "chal:"],
		["redis-code-repository.keyPrefix", "oauth:code:"],
		["redis-code-repository.defaultExpiresIn", 600],
		["redis-consent-store.keyPrefix", "consent:"],
		["redis-device-code-store.keyPrefix", "devauth:"],
		["redis-mfa-factor-store.keyPrefix", "mfaf:"],
		["redis-mfa-transaction-store.keyPrefix", "mfat:"],
		["redis-rate-limiter.failMode", "closed"],
		["redis-rate-limiter.defaultLimit", { limit: 60, windowSeconds: 60 }],
		["redis-refresh-token-family-store.keyPrefix", "rtfam:"],
		["redis-refresh-token-family-store.casRetryLimit", 3],
		["redis-replay-seen-set.keyPrefix", "replay:"],
		["redis-session-stores.keyPrefix", "ss:"],
		["redis-federation-token-store.keyPrefix", "ft:"],
		["redis-federation-token-store.ttl", 86400],
		["redis-federation-token-store.encryptionMode", "required"],
		["redis-federation-token-store.scanFallback", true],
		["redis-federation-grant-store.keyPrefix", "fg:"],
		["redis-federation-grant-store.listingAllowanceMs", 300000],
		["redis-federation-grant-store.tombstoneRetention", 2592000],
		["redis-federation-grant-store.encryptionMode", "required"],
		["redis-federation-grant-intent-store.keyPrefix", "fg:"],
	])("ships %s = %s", (path, value) => {
		expect(resolvedAt(path)).toEqual(value);
	});
});
