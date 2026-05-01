/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { redisRefreshTokenFamilyStoreModule } from "../src/index.mjs";

describe("redisRefreshTokenFamilyStoreModule", () => {
	it("has the canonical module name 'redis-refresh-token-family-store'", () => {
		expect(redisRefreshTokenFamilyStoreModule.name).toBe("redis-refresh-token-family-store");
	});

	it("requires both 'refreshTokenFamilyClient' and 'config'", () => {
		const reqs = redisRefreshTokenFamilyStoreModule.requires ?? [];
		expect(new Set(reqs)).toEqual(new Set(["refreshTokenFamilyClient", "config"]));
	});

	it("declares a Zod configSchema with module-namespaced 'redisRefreshTokenFamilyStore' top-level key only", () => {
		expect(redisRefreshTokenFamilyStoreModule.configSchema).toBeDefined();
		const parsed = redisRefreshTokenFamilyStoreModule.configSchema?.parse({}) as {
			redisRefreshTokenFamilyStore?: { keyPrefix?: string; casRetryLimit?: number };
		};
		expect(parsed?.redisRefreshTokenFamilyStore?.keyPrefix).toBe("rtfam:");
		expect(parsed?.redisRefreshTokenFamilyStore?.casRetryLimit).toBe(3);
	});

	it("validates casRetryLimit bounds (>= 1, <= 10)", () => {
		const schema = redisRefreshTokenFamilyStoreModule.configSchema;
		expect(() =>
			schema?.parse({ redisRefreshTokenFamilyStore: { keyPrefix: "k:", casRetryLimit: 0 } }),
		).toThrow();
		expect(() =>
			schema?.parse({ redisRefreshTokenFamilyStore: { keyPrefix: "k:", casRetryLimit: 11 } }),
		).toThrow();
	});
});
