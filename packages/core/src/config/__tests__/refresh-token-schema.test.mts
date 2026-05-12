/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import { describe, expect, it } from "vitest";
import { CoreConfigSchema } from "../application.schema.mjs";

/**
 * Access the refreshToken sub-schema directly so we can test the
 * preprocess wrapper that flags removed fields without standing up a
 * full AppConfig fixture.
 */
const refreshTokenSchema = CoreConfigSchema.shape.oauth.shape.refreshToken;

describe("oauth.refreshToken schema — removed-field preprocess (Phase G / M4)", () => {
	const validBase = {
		expiresIn: 86400,
		unknownFamilyPolicy: "reject" as const,
		legacyRtPolicy: "reject" as const,
	};

	it("accepts a config without any removed fields", () => {
		const result = refreshTokenSchema.safeParse(validBase);
		expect(result.success).toBe(true);
	});

	it("rejects a config that still sets legacyTokenCompat", () => {
		const result = refreshTokenSchema.safeParse({
			...validBase,
			legacyTokenCompat: true,
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		const flagged = result.error.issues.some(
			(issue) =>
				issue.path.includes("legacyTokenCompat") || issue.message.includes("legacyTokenCompat"),
		);
		expect(flagged).toBe(true);
	});

	it("rejects legacyTokenCompat=false (the value is irrelevant — presence is the failure)", () => {
		const result = refreshTokenSchema.safeParse({
			...validBase,
			legacyTokenCompat: false,
		});
		expect(result.success).toBe(false);
	});

	it("error message points operators to the migration plan", () => {
		const result = refreshTokenSchema.safeParse({
			...validBase,
			legacyTokenCompat: true,
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		const issue = result.error.issues.find((i) => i.message.includes("legacyTokenCompat"));
		expect(issue?.message).toMatch(/was removed in v0\.6\.0/);
		expect(issue?.message).toMatch(/Phase G \/ M4/);
		expect(issue?.message).toMatch(/v0\.5\.x or newer/);
	});
});

describe("oauth.refreshToken schema — legacyRtPolicy enum tightening (Phase G / M6)", () => {
	const validBase = {
		expiresIn: 86400,
		unknownFamilyPolicy: "reject" as const,
	};

	it("accepts legacyRtPolicy='reject' (the only remaining value)", () => {
		const result = refreshTokenSchema.safeParse({ ...validBase, legacyRtPolicy: "reject" });
		expect(result.success).toBe(true);
	});

	it("rejects legacyRtPolicy='accept-with-warning' (removed)", () => {
		const result = refreshTokenSchema.safeParse({
			...validBase,
			legacyRtPolicy: "accept-with-warning",
		});
		expect(result.success).toBe(false);
		if (result.success) return;
		const flagged = result.error.issues.some(
			(issue) =>
				issue.path.includes("legacyRtPolicy") || issue.message.includes("accept-with-warning"),
		);
		expect(flagged).toBe(true);
	});
});
