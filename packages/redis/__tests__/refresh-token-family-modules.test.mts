/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { describe, expect, it } from "vitest";
import { redisRefreshTokenFamilyStoreModule } from "#/index.mjs";
import { overShipped, shippedSection } from "./support/section.mjs";

describe("redisRefreshTokenFamilyStoreModule", () => {
	it("has the canonical module name 'redis-refresh-token-family-store'", () => {
		expect(redisRefreshTokenFamilyStoreModule.name).toBe("redis-refresh-token-family-store");
	});

	it("requires 'refreshTokenFamilyClient' alone", () => {
		expect(redisRefreshTokenFamilyStoreModule.requires).toEqual(["refreshTokenFamilyClient"]);
	});

	it("reads its own section, 'redis-refresh-token-family-store', with the defaults reference.conf ships", () => {
		expect(redisRefreshTokenFamilyStoreModule).not.toHaveProperty("configSchema");
		expect(
			redisRefreshTokenFamilyStoreModule.section?.schema.parse(
				shippedSection(redisRefreshTokenFamilyStoreModule),
			),
		).toEqual({
			keyPrefix: "rtfam:",
			casRetryLimit: 3,
		});
		expect(
			redisRefreshTokenFamilyStoreModule.section?.schema.parse(
				overShipped(redisRefreshTokenFamilyStoreModule, { casRetryLimit: "5" }),
			),
		).toEqual({ keyPrefix: "rtfam:", casRetryLimit: 5 });
	});

	it("validates casRetryLimit bounds (>= 1, <= 10), and refuses a key it does not declare", () => {
		const schema = redisRefreshTokenFamilyStoreModule.section?.schema;
		for (const section of [
			{ keyPrefix: "k:", casRetryLimit: 0 },
			{ keyPrefix: "k:", casRetryLimit: 11 },
			{ casRetries: 2 },
		]) {
			expect(
				schema?.safeParse(overShipped(redisRefreshTokenFamilyStoreModule, section)).success,
				JSON.stringify(section),
			).toBe(false);
		}
	});
});
