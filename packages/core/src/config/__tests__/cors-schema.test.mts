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
import { AppConfigSchema } from "#/config/application.schema.mjs";
import { makeValidAppConfig } from "#/testing/fixtures/valid-config.mjs";

/**
 * `cors.allowedOrigins` is matched against the `Origin` header by exact
 * string equality, so an entry that cannot match is an allowlist that admits
 * nobody. Nothing anywhere would say so: the config parses, the middleware
 * mounts, every request just fails at the browser. So the entries are checked
 * at boot, and each of the near-misses below is a real thing an operator types
 * — an address bar hands you the trailing slash, a URL builder hands you the
 * explicit `:443`, and a wildcard is what anyone reaches for first.
 */
function parse(allowedOrigins: unknown) {
	const config = makeValidAppConfig() as unknown as Record<string, unknown>;
	config.cors = { allowedOrigins };
	return AppConfigSchema.safeParse(config);
}

const messagesOf = (result: ReturnType<typeof parse>): string =>
	result.success ? "" : result.error.issues.map((i) => i.message).join("\n");

describe("cors.allowedOrigins — accepted shapes", () => {
	it("accepts the empty list, which is CORS off and the default", () => {
		const result = parse([]);
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.cors.allowedOrigins).toEqual([]);
	});

	it.each([
		"https://app.example.com",
		"https://app.example.com:8443",
		"http://localhost:5173",
		"http://127.0.0.1:5173",
		"http://[::1]:5173",
	])("accepts the serialized origin %s", (origin) => {
		expect(parse([origin]).success).toBe(true);
	});

	it("accepts the loopback http carve-out but not plaintext beyond it", () => {
		// The same carve-out `checkSecureEndpoint`, `checkRedirectShape` and
		// `checkRedirectUri` consume, through the one `isLoopbackHostname` home:
		// a front-end dev server works without a certificate, and a
		// plaintext origin does not get to read token responses.
		expect(parse(["http://localhost:5173"]).success).toBe(true);
		expect(parse(["http://app.example.com"]).success).toBe(false);
	});
});

describe("cors.allowedOrigins — an entry that could never match fails boot", () => {
	it.each([
		["a trailing slash", "https://app.example.com/"],
		["an explicit default port", "https://app.example.com:443"],
		["an uppercase host", "https://APP.example.com"],
		["a path", "https://app.example.com/callback"],
		["a query", "https://app.example.com?x=1"],
		["a fragment", "https://app.example.com#f"],
		["userinfo", "https://user:pass@app.example.com"],
		["a wildcard", "https://*.example.com"],
		["a bare wildcard", "*"],
		["plaintext off loopback", "http://app.example.com"],
		["something unparsable", "not-an-origin"],
		["the literal null origin", "null"],
		["a custom app scheme with no tuple origin", "com.example.app://x"],
	])("refuses %s", (_label, origin) => {
		expect(parse([origin]).success).toBe(false);
	});

	it("names the key and the index so the operator knows which entry", () => {
		const result = parse(["https://ok.example.com", "https://app.example.com/"]);
		expect(result.success).toBe(false);
		expect(messagesOf(result)).toContain("cors.allowedOrigins[1]");
	});

	it("suggests the serialized form it was probably meant to be", () => {
		expect(messagesOf(parse(["https://app.example.com/"]))).toContain('"https://app.example.com"');
	});

	it("says a wildcard matches nothing rather than just refusing it", () => {
		// The message has to explain WHY, or the operator's next move is to look
		// for the flag that turns wildcards on.
		expect(messagesOf(parse(["https://*.example.com"]))).toMatch(/exact string equality/);
	});
});

describe("cors.allowedOrigins — the CORS_ALLOWED_ORIGINS shape", () => {
	it("splits a comma-separated string, trimming each entry", () => {
		// HOCON substitutes `${?CORS_ALLOWED_ORIGINS}` as a string, always, and
		// an array of strings is not something the zod bridge can coerce
		// towards — the same wall `normalizeTrustProxy` meets.
		const result = parse(" https://app.example.com , http://localhost:5173 ");
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.cors.allowedOrigins).toEqual([
				"https://app.example.com",
				"http://localhost:5173",
			]);
		}
	});

	it("reads an exported-but-empty variable as CORS off, not as an error", () => {
		// `CORS_ALLOWED_ORIGINS=` in a .env file, a compose `environment:` entry
		// or a blank ConfigMap key. "No origins" is what both that and the unset
		// key mean, so they must agree.
		const result = parse("");
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.cors.allowedOrigins).toEqual([]);
	});

	it("drops a trailing comma rather than reporting an entry nobody wrote", () => {
		const result = parse("https://app.example.com,");
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.cors.allowedOrigins).toEqual(["https://app.example.com"]);
		}
	});

	it("still validates every entry the string carried", () => {
		expect(parse("https://app.example.com,https://*.example.com").success).toBe(false);
	});

	it("trims entries supplied as a real HOCON list too", () => {
		const result = parse([" https://app.example.com "]);
		expect(result.success).toBe(true);
		if (result.success)
			expect(result.data.cors.allowedOrigins).toEqual(["https://app.example.com"]);
	});
});

describe("cors.allowedOrigins — a shape neither reader reads refuses boot, by path", () => {
	// The key has two spellings: a list, and the one comma-separated string an
	// environment variable carries. Anything else — a number, an object, a
	// boolean, which only a configuration file can write — would otherwise read
	// as "no origins": CORS silently off for a key someone wrote.
	it.each([
		["a number", 42],
		["an object", { origin: "https://app.example.com" }],
		["a boolean", true],
	])("refuses %s, naming the key and both spellings", (_label, value) => {
		const result = parse(value);
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.issues.map((issue) => issue.path.join("."))).toEqual([
			"cors.allowedOrigins",
		]);
		expect(messagesOf(result)).toMatch(/list of origins/);
		expect(messagesOf(result)).toMatch(/comma-separated string/);
	});

	it("still reads null as no origins, as it always has", () => {
		const result = parse(null);
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.cors.allowedOrigins).toEqual([]);
	});
});
