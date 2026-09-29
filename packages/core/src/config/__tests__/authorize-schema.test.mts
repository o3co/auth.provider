/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import { parseString } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { CoreConfigSchema } from "../application.schema.mjs";

/**
 * Access the authorize sub-schema directly so we can test the preprocess
 * wrapper that flags removed fields without standing up a full AppConfig
 * fixture — same approach as refresh-token-schema.test.mts.
 */
const authorizeSchema = CoreConfigSchema.shape.oauth.shape.authorize;

describe("oauth.authorize schema — removed-field preprocess", () => {
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

describe("oauth.authorize.acrValues", () => {
	it("accepts a table of acr value → the amr values a session must carry", () => {
		const parsed = authorizeSchema.parse({
			acrValues: { "urn:example:pwd": ["pwd"], "urn:example:mfa": ["pwd", "mfa"] },
		}) as { acrValues?: Record<string, string[]> };
		expect(parsed.acrValues).toEqual({
			"urn:example:pwd": ["pwd"],
			"urn:example:mfa": ["pwd", "mfa"],
		});
	});

	it("refuses an acr that requires nothing, a non-string amr, and a non-table", () => {
		expect(authorizeSchema.safeParse({ acrValues: { "urn:x": [] } }).success).toBe(false);
		expect(authorizeSchema.safeParse({ acrValues: { "urn:x": [1] } }).success).toBe(false);
		expect(authorizeSchema.safeParse({ acrValues: "urn:x" }).success).toBe(false);
	});
});

describe("oauth.authorize.acrValues — any-of entries", () => {
	it("accepts a list of lists: any one list met satisfies the acr", () => {
		const parsed = authorizeSchema.parse({
			acrValues: { "urn:o3co:acr:phr": [["hwk"], ["swk"]], "urn:o3co:acr:mfa": ["mfa"] },
		}) as { acrValues?: Record<string, unknown> };
		expect(parsed.acrValues).toEqual({
			"urn:o3co:acr:phr": [["hwk"], ["swk"]],
			"urn:o3co:acr:mfa": ["mfa"],
		});
	});

	it("reads the HOCON the template ships for it", () => {
		const raw: unknown = parseString(
			'acrValues { "urn:o3co:acr:phr" = [["hwk"], ["swk"]] }',
		).toObject();
		expect(authorizeSchema.parse(raw)).toEqual({
			acrValues: { "urn:o3co:acr:phr": [["hwk"], ["swk"]] },
		});
	});

	it.each([
		["an alternative that requires nothing", [["hwk"], []]],
		["only an alternative that requires nothing", [[]]],
		["an empty value in an alternative", [["hwk", ""]]],
		["a list mixing values and alternatives", ["pwd", ["hwk"]]],
		["lists nested deeper", [[["hwk"]]]],
	])("refuses %s", (_label, entry) => {
		// Each would vouch for every session, or name nothing a session can carry.
		expect(authorizeSchema.safeParse({ acrValues: { "urn:x": entry } }).success).toBe(false);
	});
});
