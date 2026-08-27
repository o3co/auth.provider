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
 * Access the authorize sub-schema directly so we can test the preprocess
 * wrapper that flags removed fields without standing up a full AppConfig
 * fixture — same approach as refresh-token-schema.test.mts.
 */
const authorizeSchema = CoreConfigSchema.shape.oauth.shape.authorize;

describe("oauth.authorize schema — removed-field preprocess (#330)", () => {
	it("accepts an absent authorize section (the key is no longer required)", () => {
		const result = authorizeSchema.safeParse(undefined);
		expect(result.success).toBe(true);
	});

	it("accepts an empty authorize section (what reference.conf yields when the env var is unset)", () => {
		const result = authorizeSchema.safeParse({});
		expect(result.success).toBe(true);
	});

	it("rejects a config that still sets allowUnmarkedClients", () => {
		const result = authorizeSchema.safeParse({ allowUnmarkedClients: true });
		expect(result.success).toBe(false);
		if (result.success) return;
		const flagged = result.error.issues.some(
			(issue) =>
				issue.path.includes("allowUnmarkedClients") ||
				issue.message.includes("allowUnmarkedClients"),
		);
		expect(flagged).toBe(true);
	});

	it("rejects allowUnmarkedClients=false (the value is irrelevant — presence is the failure)", () => {
		// `false` was the strict endstate answer while the key was required, so
		// this is the config most deployments actually carry. It still fails:
		// the operator must delete the key, and a targeted error saying so beats
		// silently stripping a line the operator believes is load-bearing.
		const result = authorizeSchema.safeParse({ allowUnmarkedClients: false });
		expect(result.success).toBe(false);
	});

	it("error message tells operators to mark their clients and delete the key", () => {
		const result = authorizeSchema.safeParse({ allowUnmarkedClients: true });
		expect(result.success).toBe(false);
		if (result.success) return;
		const issue = result.error.issues.find((i) => i.message.includes("allowUnmarkedClients"));
		expect(issue?.message).toMatch(/was removed/);
		expect(issue?.message).toMatch(/firstParty: true/);
		expect(issue?.message).toMatch(/Remove this field from your config/);
	});
});
