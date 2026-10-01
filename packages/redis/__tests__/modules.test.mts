/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import {
	createRedisMfaFactorStore,
	createRedisMfaTransactionStore,
	redisChallengeStoreModule,
	redisCodeRepositoryModule,
	redisConsentStoreModule,
	redisDeviceCodeStoreModule,
	redisMfaFactorStoreModule,
	redisMfaTransactionStoreModule,
	redisReplaySeenSetModule,
} from "#/index.mjs";

describe("redisChallengeStoreModule", () => {
	it("has the canonical module name 'redis-challenge-store'", () => {
		expect(redisChallengeStoreModule.name).toBe("redis-challenge-store");
	});

	it("requires 'challengeStoreClient' alone", () => {
		expect(redisChallengeStoreModule.requires).toEqual(["challengeStoreClient"]);
	});

	it("reads its own section, 'redis-challenge-store', whose keyPrefix defaults to 'chal:'", () => {
		expect(redisChallengeStoreModule.configSchema).toBeUndefined();
		expect(redisChallengeStoreModule.section?.at).toBeUndefined();
		expect(redisChallengeStoreModule.section?.schema.parse(undefined)).toEqual({
			keyPrefix: "chal:",
		});
	});
});

describe("redisReplaySeenSetModule", () => {
	it("has the canonical module name 'redis-replay-seen-set'", () => {
		expect(redisReplaySeenSetModule.name).toBe("redis-replay-seen-set");
	});

	it("requires 'replaySeenSetClient' alone", () => {
		expect(redisReplaySeenSetModule.requires).toEqual(["replaySeenSetClient"]);
	});

	it("reads its own section, 'redis-replay-seen-set', whose keyPrefix defaults to 'replay:'", () => {
		expect(redisReplaySeenSetModule.configSchema).toBeUndefined();
		expect(redisReplaySeenSetModule.section?.at).toBeUndefined();
		expect(redisReplaySeenSetModule.section?.schema.parse(undefined)).toEqual({
			keyPrefix: "replay:",
		});
	});
});

describe("redisDeviceCodeStoreModule", () => {
	it("has the canonical module name 'redis-device-code-store'", () => {
		expect(redisDeviceCodeStoreModule.name).toBe("redis-device-code-store");
	});

	it("requires 'deviceCodeStoreClient' alone", () => {
		expect(redisDeviceCodeStoreModule.requires).toEqual(["deviceCodeStoreClient"]);
	});

	it("reads its own section, 'redis-device-code-store', whose keyPrefix defaults to 'devauth:'", () => {
		expect(redisDeviceCodeStoreModule.configSchema).toBeUndefined();
		expect(redisDeviceCodeStoreModule.section?.at).toBeUndefined();
		expect(redisDeviceCodeStoreModule.section?.schema.parse(undefined)).toEqual({
			keyPrefix: "devauth:",
		});
	});
});

describe("redisCodeRepositoryModule", () => {
	it("requires 'codeRepositoryClient', and no configuration", () => {
		expect(redisCodeRepositoryModule.requires).toEqual(["codeRepositoryClient"]);
		expect(redisCodeRepositoryModule.configSchema).toBeUndefined();
	});

	it("reads its own section, 'redis-code-repository', strict, which moved from redisCodeRepository", () => {
		expect(redisCodeRepositoryModule.section?.at).toBeUndefined();
		const schema = redisCodeRepositoryModule.section?.schema;
		expect(schema?.parse({ keyPrefix: "t:code:", defaultExpiresIn: "300" })).toEqual({
			keyPrefix: "t:code:",
			defaultExpiresIn: 300,
		});
		expect(schema?.safeParse({ defaultExpiresIn: "0" }).success).toBe(false);
		expect(schema?.safeParse({ keyPrefx: "t:" }).success).toBe(false);
		expect(redisCodeRepositoryModule.section?.relocatedFrom).toEqual({
			redisCodeRepository: "",
			"repositories.code.redis": null,
			"repositories.code.memory": null,
		});
	});
});

describe("redisConsentStoreModule", () => {
	it("has the canonical module name 'redis-consent-store'", () => {
		expect(redisConsentStoreModule.name).toBe("redis-consent-store");
	});

	it("requires both consent client slots alone", () => {
		expect(redisConsentStoreModule.requires).toEqual([
			"consentStoreClient",
			"pendingConsentStoreClient",
		]);
	});

	it("reads its own section, 'redis-consent-store', whose keyPrefix defaults to 'consent:'", () => {
		expect(redisConsentStoreModule.configSchema).toBeUndefined();
		expect(redisConsentStoreModule.section?.at).toBeUndefined();
		expect(redisConsentStoreModule.section?.schema.parse(undefined)).toEqual({
			keyPrefix: "consent:",
		});
	});
});

describe("the MFA store modules and adapters, from the package's entry", () => {
	it.each([
		[redisMfaFactorStoreModule, "redis-mfa-factor-store", "mfaFactorStoreClient", "mfaf:"],
		[
			redisMfaTransactionStoreModule,
			"redis-mfa-transaction-store",
			"mfaTransactionStoreClient",
			"mfat:",
		],
	] as const)(
		"%s.name is exported with its client slot and its own section's prefix",
		(module, name, client, prefix) => {
			expect(module.name).toBe(name);
			expect(module.requires).toEqual([client]);
			expect(module.configSchema).toBeUndefined();
			expect(module.section?.schema.parse(undefined)).toEqual({ keyPrefix: prefix });
		},
	);

	it("exports both adapters' builders", () => {
		expect(typeof createRedisMfaFactorStore).toBe("function");
		expect(typeof createRedisMfaTransactionStore).toBe("function");
	});
});
