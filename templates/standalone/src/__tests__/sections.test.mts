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
 * The schemas of the template's own modules' sections, each strict: what
 * `logging`, `http` (with its CORS list), `key-store` and `redis-clients`
 * accept, and how each refuses what it cannot use, before any module reads it.
 */

import { MAX_KID_LENGTH } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import {
	httpSectionSchema,
	inMemoryCodeRepositorySectionSchema,
	keyStoreSectionSchema,
	loggingSectionSchema,
	redisClientsSectionSchema,
} from "#/sections.mjs";

/** The shipped `http` section, with `overrides` laid over it. */
const http = (overrides: Record<string, unknown> = {}) => ({
	port: 3000,
	trustProxy: false,
	readinessTimeoutMs: 1000,
	cors: { allowedOrigins: [] },
	...overrides,
});

const parsedTrustProxy = (trustProxy: unknown) => httpSectionSchema.safeParse(http({ trustProxy }));

const issuePaths = (result: { success: boolean; error?: { issues: { path: PropertyKey[] }[] } }) =>
	result.success ? [] : (result.error?.issues ?? []).map((issue) => issue.path.join("."));

describe("logging", () => {
	it.each(["trace", "debug", "info", "warn", "error", "fatal", "silent"])(
		"accepts the level %s",
		(level) => {
			expect(loggingSectionSchema.parse({ level })).toEqual({ level });
		},
	);

	it("refuses a level it does not know", () => {
		expect(issuePaths(loggingSectionSchema.safeParse({ level: "verbose" }))).toEqual(["level"]);
	});

	it("refuses a key it does not declare", () => {
		expect(loggingSectionSchema.safeParse({ level: "info", format: "json" }).success).toBe(false);
	});
});

describe("http.trustProxy — boolean", () => {
	it.each([false, true])("accepts the boolean %s unchanged", (value) => {
		const result = parsedTrustProxy(value);
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.trustProxy).toBe(value);
	});

	it.each([
		["true", true],
		["false", false],
	])("reads the variable's string %s as a boolean", (raw, expected) => {
		const result = parsedTrustProxy(raw);
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.trustProxy).toBe(expected);
	});

	it("reads an exported-but-empty variable as `false`, trusting nothing", () => {
		const result = parsedTrustProxy("");
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.trustProxy).toBe(false);
	});
});

describe("http.trustProxy — hop count", () => {
	it.each([0, 1, 3])("accepts the hop count %s", (value) => {
		const result = parsedTrustProxy(value);
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.trustProxy).toBe(value);
	});

	it("reads a numeric string as a hop count, not as a one-entry address list", () => {
		const result = parsedTrustProxy("2");
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.trustProxy).toBe(2);
	});

	it.each([
		["a negative hop count", -1],
		["a fractional hop count", 1.5],
		["a hop count above the ceiling", 100_000],
	])("refuses %s", (_what, value) => {
		expect(parsedTrustProxy(value).success).toBe(false);
	});
});

describe("http.trustProxy — address list", () => {
	it.each([
		[["10.0.0.7", "2001:db8::1"]],
		[["10.0.0.0/8", "fc00::/7"]],
		[["loopback"]],
		[["linklocal"]],
		[["uniquelocal"]],
	])("accepts %j", (list) => {
		const result = parsedTrustProxy(list);
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.trustProxy).toEqual(list);
	});

	it("splits a comma-separated string into entries, trimming each", () => {
		const result = parsedTrustProxy("10.0.0.0/8, 192.168.0.0/16");
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.trustProxy).toEqual(["10.0.0.0/8", "192.168.0.0/16"]);
	});

	it("reads a single entry as a one-entry list", () => {
		const result = parsedTrustProxy("loopback");
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.trustProxy).toEqual(["loopback"]);
	});

	it("refuses an empty list", () => {
		expect(parsedTrustProxy([]).success).toBe(false);
	});

	it("refuses a hostname, naming its index", () => {
		expect(issuePaths(parsedTrustProxy(["proxy.internal"]))).toContain("trustProxy.0");
	});

	it("names the offending index of a longer list", () => {
		expect(issuePaths(parsedTrustProxy(["loopback", "10.0.0.0/8", "10.0.0.0/33"]))).toContain(
			"trustProxy.2",
		);
	});

	it("refuses dotted-netmask notation, naming the prefix-length form", () => {
		const result = parsedTrustProxy(["10.0.0.0/255.0.0.0"]);
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((issue) => /prefix length/i.test(issue.message))).toBe(true);
		}
	});

	it.each([[[42]], [null], [{}]])("refuses %j", (value) => {
		expect(parsedTrustProxy(value).success).toBe(false);
	});

	it("is required", () => {
		const { trustProxy: _dropped, ...rest } = http();
		expect(issuePaths(httpSectionSchema.safeParse(rest))).toContain("trustProxy");
	});
});

describe("http.cors.allowedOrigins", () => {
	const parsed = (allowedOrigins: unknown) =>
		httpSectionSchema.safeParse(http({ cors: { allowedOrigins } }));
	const messagesOf = (result: ReturnType<typeof parsed>): string =>
		result.success ? "" : result.error.issues.map((issue) => issue.message).join("\n");

	it("accepts the empty list, CORS off", () => {
		const result = parsed([]);
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
		expect(parsed([origin]).success).toBe(true);
	});

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
		expect(parsed([origin]).success).toBe(false);
	});

	it("names the key and the index of an entry that could never match", () => {
		const result = parsed(["https://ok.example.com", "https://app.example.com/"]);
		expect(messagesOf(result)).toContain("http.cors.allowedOrigins[1]");
		expect(issuePaths(result)).toEqual(["cors.allowedOrigins.1"]);
	});

	it("suggests the serialized form an entry was probably meant to be", () => {
		expect(messagesOf(parsed(["https://app.example.com/"]))).toContain('"https://app.example.com"');
	});

	it("says a wildcard matches nothing, rather than only refusing it", () => {
		expect(messagesOf(parsed(["https://*.example.com"]))).toMatch(/exact string equality/);
	});

	it("splits the variable's comma-separated string, trimming each entry and dropping a trailing comma", () => {
		const result = parsed(" https://app.example.com , http://localhost:5173 ,");
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.cors.allowedOrigins).toEqual([
				"https://app.example.com",
				"http://localhost:5173",
			]);
		}
	});

	it("reads an exported-but-empty variable, and null, as no origins", () => {
		for (const value of ["", null]) {
			const result = parsed(value);
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.cors.allowedOrigins).toEqual([]);
		}
	});

	it("checks every entry the string carried", () => {
		expect(parsed("https://app.example.com,https://*.example.com").success).toBe(false);
	});

	it.each([
		["a number", 42],
		["an object", { origin: "https://app.example.com" }],
		["a boolean", true],
	])("refuses %s, naming the key, both spellings and the new variable", (_label, value) => {
		const result = parsed(value);
		expect(issuePaths(result)).toEqual(["cors.allowedOrigins"]);
		expect(messagesOf(result)).toMatch(/list of origins/);
		expect(messagesOf(result)).toMatch(/comma-separated string/);
		expect(messagesOf(result)).toContain("HTTP_CORS_ALLOWED_ORIGINS");
	});
});

describe("http — the rest of the section", () => {
	it("reads the port and the readiness deadline from the variables' strings", () => {
		expect(
			httpSectionSchema.parse(http({ port: "8080", readinessTimeoutMs: "1500" })),
		).toMatchObject({ port: 8080, readinessTimeoutMs: 1500 });
	});

	it.each([
		["a blank variable", ""],
		["zero", 0],
		["a negative deadline", -1],
		["a fractional deadline", 1.5],
		["a deadline beyond Node's timer range", 2_147_483_648],
	])("refuses %s as the readiness deadline", (_what, readinessTimeoutMs) => {
		expect(issuePaths(httpSectionSchema.safeParse(http({ readinessTimeoutMs })))).toEqual([
			"readinessTimeoutMs",
		]);
	});

	describe("the readiness deadline is read in decimal digits", () => {
		const MESSAGE = "must be a whole number from 1 to 2147483647, in decimal digits";
		const messagesAt = (readinessTimeoutMs: unknown) =>
			(httpSectionSchema.safeParse(http({ readinessTimeoutMs })).error?.issues ?? [])
				.filter((issue) => issue.path.join(".") === "readinessTimeoutMs")
				.map((issue) => issue.message);

		it.each([
			["0x10"],
			["1e3"],
			["5.0"],
			["+5"],
			[true],
			[""],
			["  "],
			["Infinity"],
			[0],
			[2_147_483_648],
		])("refuses %j, naming the range", (readinessTimeoutMs) => {
			expect(messagesAt(readinessTimeoutMs)).toEqual([MESSAGE]);
		});

		it.each([[60], ["60"], [" 60 "]])("reads %j as 60", (readinessTimeoutMs) => {
			expect(httpSectionSchema.parse(http({ readinessTimeoutMs })).readinessTimeoutMs).toBe(60);
		});
	});

	it.each([
		[8080, 8080],
		[" 8080 ", 8080],
		[65_535, 65_535],
	])("reads the port %j as %j", (port, read) => {
		expect(httpSectionSchema.parse(http({ port })).port).toBe(read);
	});

	it.each([0, "0"])("keeps an explicit %j as the port, the OS choosing a free one", (port) => {
		expect(httpSectionSchema.parse(http({ port })).port).toBe(0);
	});

	it.each([
		["the empty string an exported-but-empty HTTP_PORT carries", ""],
		["a blank variable", "  "],
		["hexadecimal", "0x50"],
		["an exponent", "8e3"],
		["a sign", "+80"],
		["a negative number", -1],
		["a fraction", 80.5],
		["a number above 65535", 65_536],
		["a number above 65535, as the variable's string", "65536"],
		["null", null],
		["true", true],
	])("refuses %s as the port, naming http.port and HTTP_PORT", (_what, port) => {
		const result = httpSectionSchema.safeParse(http({ port }));
		expect(issuePaths(result)).toEqual(["port"]);
		const message = result.error?.issues.map((issue) => issue.message).join("\n");
		expect(message).toContain("http.port");
		expect(message).toContain("HTTP_PORT");
	});

	it.each([
		["a key the section does not declare", http({ host: "0.0.0.0" })],
		["a key cors does not declare", http({ cors: { allowedOrigins: [], credentials: true } })],
	])("refuses %s", (_what, section) => {
		expect(httpSectionSchema.safeParse(section).success).toBe(false);
	});
});

/** A `local` block with every field an HS256 one takes, `overrides` laid over it. */
const hs256 = (overrides: Record<string, unknown> = {}) => ({
	algorithm: "HS256",
	kid: "v0",
	secret: "s3cret",
	previousSecrets: [],
	...overrides,
});

describe("key-store", () => {
	it("accepts provider local with its local block", () => {
		expect(keyStoreSectionSchema.parse({ provider: "local", local: hs256() })).toEqual({
			provider: "local",
			local: hs256(),
		});
	});

	it("requires provider", () => {
		expect(issuePaths(keyStoreSectionSchema.safeParse({ local: hs256() }))).toContain("provider");
	});

	it("refuses a block the section does not declare", () => {
		expect(
			keyStoreSectionSchema.safeParse({ provider: "kms", kms: { keyArn: "arn:aws:..." } }).success,
		).toBe(false);
	});

	it("leaves the key material to the key store: HS256 without a secret parses", () => {
		expect(
			keyStoreSectionSchema.safeParse({
				provider: "local",
				local: { algorithm: "HS256", kid: "v0", previousSecrets: [] },
			}).success,
		).toBe(true);
	});

	it("accepts HS256 rotation through previousSecrets, and refuses previousKeys under HS256", () => {
		const previous = { kid: "v-old", expiresAt: "2099-12-31T00:00:00Z" };
		expect(
			keyStoreSectionSchema.safeParse({
				provider: "local",
				local: hs256({ previousSecrets: [{ ...previous, secret: "old-secret" }] }),
			}).success,
		).toBe(true);
		expect(
			keyStoreSectionSchema.safeParse({
				provider: "local",
				local: hs256({ previousKeys: [{ ...previous, publicKey: "...pem..." }] }),
			}).success,
		).toBe(false);
	});

	it("accepts an asymmetric block carrying the secret the reference binds for every algorithm", () => {
		expect(
			keyStoreSectionSchema.safeParse({
				provider: "local",
				local: { algorithm: "EdDSA", kid: "v0", privateKey: "p", publicKey: "q", secret: "s" },
			}).success,
		).toBe(true);
	});

	it("refuses a key an asymmetric block does not declare", () => {
		expect(
			keyStoreSectionSchema.safeParse({
				provider: "local",
				local: { algorithm: "EdDSA", kid: "v0", privateKeyPth: "/keys/p.pem" },
			}).success,
		).toBe(false);
	});

	it("refuses an algorithm it does not know", () => {
		expect(
			keyStoreSectionSchema.safeParse({ provider: "local", local: hs256({ algorithm: "none" }) })
				.success,
		).toBe(false);
	});

	describe.each([
		["longer than MAX_KID_LENGTH", "k".repeat(MAX_KID_LENGTH + 1)],
		["empty", ""],
		["carrying a line feed", "v1\nv2"],
		["not a string", 7],
	])("a kid %s", (_label, kid) => {
		const parse = (local: Record<string, unknown>) =>
			keyStoreSectionSchema.safeParse({ provider: "local", local }).success;
		const ed25519 = { algorithm: "EdDSA", kid: "v0", privateKey: "p", publicKey: "q" };
		const at = "2030-01-01T00:00:00Z";

		it("is refused as the current kid, and in previousSecrets and previousKeys", () => {
			expect(parse(hs256({ kid }))).toBe(false);
			expect(parse(hs256({ previousSecrets: [{ kid, secret: "s", expiresAt: at }] }))).toBe(false);
			expect(parse({ ...ed25519, kid })).toBe(false);
			expect(parse({ ...ed25519, previousKeys: [{ kid, publicKey: "q", expiresAt: at }] })).toBe(
				false,
			);
		});
	});
});

describe("redis-clients", () => {
	it("accepts a URL, and a password beside it", () => {
		expect(
			redisClientsSectionSchema.parse({
				url: "redis://r:6379",
				password: "p",
				assumeNoEviction: false,
			}),
		).toEqual({
			url: "redis://r:6379",
			password: "p",
			assumeNoEviction: false,
		});
		expect(
			redisClientsSectionSchema.parse({ url: "redis://r:6379", assumeNoEviction: false }),
		).toEqual({
			url: "redis://r:6379",
			assumeNoEviction: false,
		});
	});

	it.each([
		[true, true],
		["true", true],
		["1", true],
		["false", false],
		["", false],
	])("reads assumeNoEviction %j as %s", (given, read) => {
		expect(
			redisClientsSectionSchema.parse({ url: "redis://r:6379", assumeNoEviction: given })
				.assumeNoEviction,
		).toBe(read);
	});

	it("refuses an assumeNoEviction it cannot read as a boolean, naming the key", () => {
		const parsed = redisClientsSectionSchema.safeParse({
			url: "redis://r:6379",
			assumeNoEviction: "yes",
		});
		expect(parsed.success).toBe(false);
		expect(parsed.error?.issues[0]?.path).toEqual(["assumeNoEviction"]);
	});

	it.each([
		["no URL", {}],
		["a null URL", { url: null }],
		[
			"a key the section does not declare",
			{ url: "redis://r:6379", db: 2, assumeNoEviction: false },
		],
		["no assumeNoEviction, which the template's reference.conf ships", { url: "redis://r:6379" }],
	])("refuses %s", (_what, section) => {
		expect(redisClientsSectionSchema.safeParse(section).success).toBe(false);
	});
});

describe("the in-process code repository", () => {
	const MESSAGE = "must be a whole number of at least 1, in decimal digits";
	const messagesAt = (defaultExpiresIn: unknown) =>
		(inMemoryCodeRepositorySectionSchema.safeParse({ defaultExpiresIn }).error?.issues ?? [])
			.filter((issue) => issue.path.join(".") === "defaultExpiresIn")
			.map((issue) => issue.message);

	it.each([["0x10"], ["1e3"], ["5.0"], ["+5"], [true], [""], ["  "], ["Infinity"], [0], ["0"]])(
		"refuses %j as defaultExpiresIn, naming the range",
		(defaultExpiresIn) => {
			expect(messagesAt(defaultExpiresIn)).toEqual([MESSAGE]);
		},
	);

	it.each([[60], ["60"], [" 60 "]])("reads %j as defaultExpiresIn 60", (defaultExpiresIn) => {
		expect(inMemoryCodeRepositorySectionSchema.parse({ defaultExpiresIn }).defaultExpiresIn).toBe(
			60,
		);
	});
});
