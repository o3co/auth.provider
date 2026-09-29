/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import {
	createRedisMfaFactorStore,
	createRedisMfaTransactionStore,
	redisChallengeStoreModule,
	redisConsentStoreModule,
	redisDeviceCodeStoreModule,
	redisMfaFactorStoreModule,
	redisMfaTransactionStoreModule,
	redisReplaySeenSetModule,
} from "../src/index.mjs";

describe("redisChallengeStoreModule", () => {
	it("has the canonical module name 'redis-challenge-store'", () => {
		expect(redisChallengeStoreModule.name).toBe("redis-challenge-store");
	});

	it("requires both 'challengeStoreClient' and 'config'", () => {
		const reqs = redisChallengeStoreModule.requires ?? [];
		expect(new Set(reqs)).toEqual(new Set(["challengeStoreClient", "config"]));
	});

	it("declares a Zod configSchema with module-namespaced 'redisChallengeStore' top-level key only", () => {
		expect(redisChallengeStoreModule.configSchema).toBeDefined();
		const parsed = redisChallengeStoreModule.configSchema?.parse({}) as {
			redisChallengeStore?: { keyPrefix?: string };
		};
		expect(parsed?.redisChallengeStore?.keyPrefix).toBe("chal:");
	});
});

describe("redisReplaySeenSetModule", () => {
	it("has the canonical module name 'redis-replay-seen-set'", () => {
		expect(redisReplaySeenSetModule.name).toBe("redis-replay-seen-set");
	});

	it("requires both 'replaySeenSetClient' and 'config'", () => {
		const reqs = redisReplaySeenSetModule.requires ?? [];
		expect(new Set(reqs)).toEqual(new Set(["replaySeenSetClient", "config"]));
	});

	it("declares a Zod configSchema with module-namespaced 'redisReplaySeenSet' top-level key only", () => {
		expect(redisReplaySeenSetModule.configSchema).toBeDefined();
		const parsed = redisReplaySeenSetModule.configSchema?.parse({}) as {
			redisReplaySeenSet?: { keyPrefix?: string };
		};
		expect(parsed?.redisReplaySeenSet?.keyPrefix).toBe("replay:");
	});
});

describe("redisDeviceCodeStoreModule", () => {
	it("has the canonical module name 'redis-device-code-store'", () => {
		expect(redisDeviceCodeStoreModule.name).toBe("redis-device-code-store");
	});

	it("requires both 'deviceCodeStoreClient' and 'config'", () => {
		const reqs = redisDeviceCodeStoreModule.requires ?? [];
		expect(new Set(reqs)).toEqual(new Set(["deviceCodeStoreClient", "config"]));
	});

	it("declares a Zod configSchema with module-namespaced 'redisDeviceCodeStore' top-level key only", () => {
		expect(redisDeviceCodeStoreModule.configSchema).toBeDefined();
		const parsed = redisDeviceCodeStoreModule.configSchema?.parse({}) as {
			redisDeviceCodeStore?: { keyPrefix?: string };
		};
		expect(parsed?.redisDeviceCodeStore?.keyPrefix).toBe("devauth:");
	});
});

describe("redisConsentStoreModule", () => {
	it("has the canonical module name 'redis-consent-store'", () => {
		expect(redisConsentStoreModule.name).toBe("redis-consent-store");
	});

	it("requires both consent client slots and 'config'", () => {
		const reqs = redisConsentStoreModule.requires ?? [];
		expect(new Set(reqs)).toEqual(
			new Set(["consentStoreClient", "pendingConsentStoreClient", "config"]),
		);
	});

	it("declares a Zod configSchema with module-namespaced 'redisConsentStore' top-level key only", () => {
		expect(redisConsentStoreModule.configSchema).toBeDefined();
		const parsed = redisConsentStoreModule.configSchema?.parse({}) as {
			redisConsentStore?: { keyPrefix?: string };
		};
		expect(parsed?.redisConsentStore?.keyPrefix).toBe("consent:");
	});
});

describe("the MFA store modules and adapters, from the package's entry", () => {
	it.each([
		[
			redisMfaFactorStoreModule,
			"redis-mfa-factor-store",
			"mfaFactorStoreClient",
			"redisMfaFactorStore",
			"mfaf:",
		],
		[
			redisMfaTransactionStoreModule,
			"redis-mfa-transaction-store",
			"mfaTransactionStoreClient",
			"redisMfaTransactionStore",
			"mfat:",
		],
	] as const)(
		"%s.name is exported with its client slot and its namespaced prefix",
		(module, name, client, key, prefix) => {
			expect(module.name).toBe(name);
			expect(new Set(module.requires ?? [])).toEqual(new Set([client, "config"]));
			const parsed = (module.configSchema?.parse({}) ?? {}) as Record<
				string,
				{ keyPrefix?: string }
			>;
			expect(parsed[key]?.keyPrefix).toBe(prefix);
		},
	);

	it("exports both adapters' builders", () => {
		expect(typeof createRedisMfaFactorStore).toBe("function");
		expect(typeof createRedisMfaTransactionStore).toBe("function");
	});
});
