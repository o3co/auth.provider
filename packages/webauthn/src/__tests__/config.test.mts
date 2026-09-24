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

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { AppConfigSchema } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { webauthnConfigSchema } from "../config.mjs";

// Per ADR 2026-04-30: schema is a pure type contract; defaults live in
// packages/webauthn/config/reference.conf (not in Zod .default() calls).
// Tests must supply all required fields explicitly — the minimum-valid test
// verifies the schema shape and S11-mandated field values.
/**
 * Every field the schema requires, minus the one under test. Spelled out
 * rather than derived so a new required field forces this file to be updated
 * deliberately (ADR 2026-04-30: no schema-side defaults).
 */
const VALID = {
	rpId: "example.com",
	rpName: "Example App",
	origin: ["https://example.com"],
	// S11: attestationPreference = "none" is the dogfood-friendly baseline.
	// In production this comes from reference.conf; tests supply it explicitly
	// per ADR 2026-04-30 (no schema-side defaults).
	attestationPreference: "none",
	userVerification: "preferred",
	challengeTtlMs: 120_000,
	allowCredentialsForKnownUser: false,
	rateLimit: { authenticationOptions: { limit: 30, windowSeconds: 60 } },
};

const without = (key: keyof typeof VALID) => {
	const { [key]: _dropped, ...rest } = VALID;
	return rest;
};

describe("webauthnConfigSchema (spec §2.4.1)", () => {
	it("accepts minimum valid config with all required fields", () => {
		const parsed = webauthnConfigSchema.parse(VALID);
		expect(parsed.attestationPreference).toBe("none"); // S11 default value
		expect(parsed.userVerification).toBe("preferred");
		expect(parsed.challengeTtlMs).toBe(120_000); // mobile-network safe baseline
	});

	it("rejects missing rpId", () => {
		expect(webauthnConfigSchema.safeParse(without("rpId")).success).toBe(false);
	});

	it("origin must be non-empty array", () => {
		expect(webauthnConfigSchema.safeParse({ ...VALID, origin: [] }).success).toBe(false);
	});

	it("attestationPreference enum is constrained", () => {
		expect(
			webauthnConfigSchema.safeParse({ ...VALID, attestationPreference: "bogus" }).success,
		).toBe(false);
	});

	// #281 — the enumeration escape hatch and the endpoint's own throttle.
	describe("authentication/options security knobs (#281)", () => {
		it("allowCredentialsForKnownUser is required — there is no implicit fallback", () => {
			expect(webauthnConfigSchema.safeParse(without("allowCredentialsForKnownUser")).success).toBe(
				false,
			);
		});

		it("allowCredentialsForKnownUser refuses what is not a boolean spelling", () => {
			// Core's `coerceBooleanFromEnv` vocabulary: "true" / "false" / "1" / "0"
			// (and "" as false). Anything else fails at boot rather than being
			// read as whichever value `Boolean(value)` would guess.
			for (const bad of ["yes", "on", "ture", 2]) {
				expect(
					webauthnConfigSchema.safeParse({ ...VALID, allowCredentialsForKnownUser: bad }).success,
					String(bad),
				).toBe(false);
			}
		});

		it("carries the opt-in through to the parsed config", () => {
			const parsed = webauthnConfigSchema.parse({ ...VALID, allowCredentialsForKnownUser: true });
			expect(parsed.allowCredentialsForKnownUser).toBe(true);
		});

		it("rateLimit.authenticationOptions is required", () => {
			expect(webauthnConfigSchema.safeParse(without("rateLimit")).success).toBe(false);
		});

		it("coerces the HOCON/env string form into numbers", () => {
			const parsed = webauthnConfigSchema.parse({
				...VALID,
				rateLimit: { authenticationOptions: { limit: "45", windowSeconds: "120" } },
			});
			expect(parsed.rateLimit.authenticationOptions).toEqual({ limit: 45, windowSeconds: 120 });
		});

		it("rejects a non-positive limit or window", () => {
			for (const bad of [
				{ limit: 0, windowSeconds: 60 },
				{ limit: 30, windowSeconds: 0 },
				{ limit: -1, windowSeconds: 60 },
				{ limit: 1.5, windowSeconds: 60 },
			]) {
				expect(
					webauthnConfigSchema.safeParse({ ...VALID, rateLimit: { authenticationOptions: bad } })
						.success,
				).toBe(false);
			}
		});
	});

	// HOCON substitutes `${?VAR}` as a string, always, so an operator who sets
	// one of these variables hands the schema a string. Core's schema coerces
	// every leaf an env var can reach (#288); these two were bare `z.number()` /
	// `z.boolean()` and refused the string their own reference.conf delivers.
	describe("env-reachable leaves take the string an env substitution delivers", () => {
		const referenceConf = readFileSync(
			fileURLToPath(new URL("../../config/reference.conf", import.meta.url)),
			"utf8",
		);

		it("reference.conf lets the environment reach both leaves", () => {
			expect(referenceConf).toMatch(/^\s*challengeTtlMs = \$\{\?WEBAUTHN_CHALLENGE_TTL_MS\}$/m);
			expect(referenceConf).toMatch(
				/^\s*allowCredentialsForKnownUser = \$\{\?WEBAUTHN_ALLOW_CREDENTIALS_FOR_KNOWN_USER\}$/m,
			);
		});

		it("WEBAUTHN_CHALLENGE_TTL_MS=60000 parses to the number 60000", () => {
			const parsed = webauthnConfigSchema.parse({ ...VALID, challengeTtlMs: "60000" });
			expect(parsed.challengeTtlMs).toBe(60_000);
		});

		it("WEBAUTHN_ALLOW_CREDENTIALS_FOR_KNOWN_USER parses to a boolean", () => {
			for (const [raw, expected] of [
				["true", true],
				["false", false],
				["1", true],
				["0", false],
				// An exported-but-empty variable: off, as everywhere in core.
				["", false],
			] as const) {
				const parsed = webauthnConfigSchema.parse({ ...VALID, allowCredentialsForKnownUser: raw });
				expect(parsed.allowCredentialsForKnownUser, JSON.stringify(raw)).toBe(expected);
			}
		});

		it("still refuses a TTL that is not a positive integer, in the string form too", () => {
			for (const bad of ["", "0", "-1", "1.5", "60s", "abc", 0, -1]) {
				expect(
					webauthnConfigSchema.safeParse({ ...VALID, challengeTtlMs: bad }).success,
					JSON.stringify(bad),
				).toBe(false);
			}
		});
	});

	// Wave 1 post-merge audit M-1 + follow-up review I2:
	// URL-parse-based origin gate must reject textual-prefix bypasses.
	describe("origin secure-context gate (M-1 / I2)", () => {
		const { origin: _origin, ...okBase } = VALID;
		const accepts = [
			"https://example.com",
			"https://app.example.com:8443",
			"http://localhost",
			"http://localhost:3000",
			"http://127.0.0.1",
			"http://127.0.0.1:8080",
			"http://[::1]",
			"http://[::1]:9000",
		];
		const rejects = [
			"http://example.com", // non-loopback http
			"file:///etc/passwd",
			"javascript:alert(1)",
			"https://*.example.com", // wildcard
			"http://127.0.0.1.evil.com", // hostname-prefix bypass
			"http://127.0.0.1@evil.com", // userinfo bypass (loopback in user)
			"http://[::1]@evil.com", // userinfo bypass (ipv6 in user)
			"https://user:pass@example.com", // userinfo present
			"http://localhost@evil.com", // userinfo bypass (loopback hostname in user)
		];

		for (const origin of accepts) {
			it(`accepts ${origin}`, () => {
				expect(webauthnConfigSchema.safeParse({ ...okBase, origin: [origin] }).success).toBe(true);
			});
		}

		for (const origin of rejects) {
			it(`rejects ${origin}`, () => {
				expect(webauthnConfigSchema.safeParse({ ...okBase, origin: [origin] }).success).toBe(false);
			});
		}
	});

	// SimpleWebAuthn compares each entry with the browser's clientDataJSON
	// origin by exact string, and a browser sends the serialized origin. An
	// entry that is not one — a trailing slash, a path, an uppercase host, an
	// explicit default port — parses, and then matches no ceremony. Both lists
	// hold web entries to core's serialized-origin rule (`checkSerializedOrigin`),
	// the one `cors.allowedOrigins` is held to, with the loopback carve-out
	// core's vocabulary names.
	describe("web entries are bare serialized origins, in both lists", () => {
		const { origin: _origin, ...okBase } = VALID;
		const notSerialized = [
			"https://example.com/",
			"https://example.com/app",
			"https://EXAMPLE.com",
			"https://example.com:443",
			"https://example.com?x=1",
			"https://example.com#f",
		];
		for (const entry of notSerialized) {
			it(`refuses ${entry}`, () => {
				expect(webauthnConfigSchema.safeParse({ ...okBase, origin: [entry] }).success).toBe(false);
				expect(webauthnConfigSchema.safeParse({ ...VALID, topOrigin: [entry] }).success).toBe(
					false,
				);
			});
		}

		it("names the index and says what the entry should have been", () => {
			const result = webauthnConfigSchema.safeParse({
				...okBase,
				origin: ["https://example.com", "https://app.example.com/"],
			});
			expect(result.error?.issues[0]?.path).toEqual(["origin", 1]);
			expect(result.error?.issues[0]?.message).toContain('"https://app.example.com"');
		});

		it("accepts http for the whole 127.0.0.0/8 loopback block, as core's vocabulary names it", () => {
			expect(
				webauthnConfigSchema.safeParse({ ...okBase, origin: ["http://127.0.0.53:3000"] }).success,
			).toBe(true);
			expect(
				webauthnConfigSchema.safeParse({ ...VALID, topOrigin: ["http://127.0.0.53:3000"] }).success,
			).toBe(true);
		});
	});

	// #497: Android Credential Manager presents `android:apk-key-hash:<base64url>`
	// as the ceremony origin, and SimpleWebAuthn — which this package delegates
	// verification to — matches it by exact string like any other origin. The
	// secure-context gate above knew only about `https:` and loopback `http:`,
	// so the "one RP shared by the web origin and the Android app" deployment
	// the README describes could not be expressed in configuration at all.
	describe("Android apk-key-hash origins (#497)", () => {
		const { origin: _origin, ...okBase } = VALID;
		// A real Credential Manager origin is the SHA-256 of the app's signing
		// certificate, base64url-encoded — 43 characters, unpadded.
		const androidOrigin = "android:apk-key-hash:pNiP5iKyQ8JwgLTSKGZmcRHqvOUP1qGP8FfEcCQPvVI";

		const accepts = [
			androidOrigin,
			// Padded base64url is still base64url; some tooling emits it.
			"android:apk-key-hash:pNiP5iKyQ8JwgLTSKGZmcRHqvOU=",
			// The `-` and `_` of the URL-safe alphabet.
			"android:apk-key-hash:-_ab12",
		];

		const rejects = [
			// Empty body — the prefix on its own names no app.
			"android:apk-key-hash:",
			// Standard base64's `+` and `/` are not the URL-safe alphabet, and an
			// authenticator never sends them.
			"android:apk-key-hash:abc+def",
			"android:apk-key-hash:abc/def",
			// Trailing junk after the body.
			"android:apk-key-hash:abcdef/../evil",
			"android:apk-key-hash:abcdef?x=1",
			"android:apk-key-hash:abcdef#frag",
			// A different `android:` sub-scheme is not the one Credential
			// Manager sends, so it could only ever be a dead entry.
			"android:apk-key-hash-sha256:abcdef",
			"android:package:com.example.app",
			// Case matters: the client sends the lowercase spelling, and
			// SimpleWebAuthn compares exactly.
			"ANDROID:APK-KEY-HASH:abcdef",
			// Wildcards stay refused here too.
			"android:apk-key-hash:*",
		];

		for (const origin of accepts) {
			it(`accepts ${origin}`, () => {
				expect(webauthnConfigSchema.safeParse({ ...okBase, origin: [origin] }).success).toBe(true);
			});
		}

		for (const origin of rejects) {
			it(`rejects ${origin}`, () => {
				expect(webauthnConfigSchema.safeParse({ ...okBase, origin: [origin] }).success).toBe(false);
			});
		}

		it("shares one RP between the web origin and the Android app", () => {
			// The deployment the README documents: one `rpId`, two origins.
			const parsed = webauthnConfigSchema.parse({
				...okBase,
				origin: ["https://example.com", androidOrigin],
			});
			expect(parsed.origin).toEqual(["https://example.com", androidOrigin]);
		});
	});
});

describe("topOrigin — the origins this RP may be framed by (#554 audit)", () => {
	const base = VALID;

	it("is optional, and absent means this RP expects not to be framed", () => {
		const parsed = webauthnConfigSchema.parse(base);
		expect(parsed.topOrigin).toBeUndefined();
	});

	it("accepts https origins, and the loopback carve-out the origin list has", () => {
		expect(
			webauthnConfigSchema.parse({
				...base,
				topOrigin: ["https://embedder.example", "http://localhost:3000"],
			}).topOrigin,
		).toEqual(["https://embedder.example", "http://localhost:3000"]);
	});

	it("refuses what the origin list refuses — a wildcard, a trailing slash, a bare host", () => {
		for (const bad of [
			["https://*.example.com"],
			["https://embedder.example/"],
			["embedder.example"],
			["http://embedder.example"],
		]) {
			expect(() => webauthnConfigSchema.parse({ ...base, topOrigin: bad }), String(bad)).toThrow();
		}
	});

	it("refuses an Android app origin: a top origin is a browsing context", () => {
		// `android:apk-key-hash:` is what Credential Manager sends *as* the
		// origin; there is no frame above it, so it is not a top origin.
		expect(() =>
			webauthnConfigSchema.parse({
				...base,
				topOrigin: ["android:apk-key-hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
			}),
		).toThrow();
	});
});

// HOCON substitutes `${?WEBAUTHN_ORIGIN}` / `${?WEBAUTHN_TOP_ORIGIN}` as one
// string, and an environment variable has no other way to carry a list. The
// list therefore takes the spelling core gives `CORS_ALLOWED_ORIGINS`:
// comma-separated, each entry trimmed, empty entries dropped. The split yields
// only pieces of what the operator wrote, each validated as a list entry
// would be, so the string cannot admit an origin the list would refuse.
describe("origin lists from the environment (WEBAUTHN_ORIGIN / WEBAUTHN_TOP_ORIGIN)", () => {
	const referenceConf = readFileSync(
		fileURLToPath(new URL("../../config/reference.conf", import.meta.url)),
		"utf8",
	);
	const ANDROID = "android:apk-key-hash:pNiP5iKyQ8JwgLTSKGZmcRHqvOUP1qGP8FfEcCQPvVI";

	it("reference.conf lets the environment reach both lists", () => {
		expect(referenceConf).toMatch(/^\s*origin = \$\{\?WEBAUTHN_ORIGIN\}$/m);
		expect(referenceConf).toMatch(/^\s*topOrigin = \$\{\?WEBAUTHN_TOP_ORIGIN\}$/m);
	});

	it("reads a single origin as a one-entry list", () => {
		expect(webauthnConfigSchema.parse({ ...VALID, origin: "https://example.com" }).origin).toEqual([
			"https://example.com",
		]);
	});

	it("splits a comma-separated WEBAUTHN_ORIGIN into its origins, web and Android alike", () => {
		const parsed = webauthnConfigSchema.parse({
			...VALID,
			origin: `https://a.example,https://b.example,${ANDROID}`,
		});
		expect(parsed.origin).toEqual(["https://a.example", "https://b.example", ANDROID]);
	});

	it("trims each entry and drops the empty ones, as CORS_ALLOWED_ORIGINS does", () => {
		const parsed = webauthnConfigSchema.parse({
			...VALID,
			origin: " https://a.example , ,https://b.example ,",
		});
		expect(parsed.origin).toEqual(["https://a.example", "https://b.example"]);
	});

	it("refuses a malformed entry in the string exactly as it does in the list", () => {
		for (const bad of [
			"https://a.example,https://*.example.com",
			"https://a.example,http://insecure.example",
			"https://a.example,https://user@b.example",
			"https://a.example,a.example",
		]) {
			expect(webauthnConfigSchema.safeParse({ ...VALID, origin: bad }).success, bad).toBe(false);
			expect(
				webauthnConfigSchema.safeParse({ ...VALID, origin: bad.split(",") }).success,
				`${bad} as a list`,
			).toBe(false);
		}
	});

	it("refuses an empty WEBAUTHN_ORIGIN: the relying party needs at least one origin", () => {
		expect(webauthnConfigSchema.safeParse({ ...VALID, origin: "" }).success).toBe(false);
		expect(webauthnConfigSchema.safeParse({ ...VALID, origin: " , " }).success).toBe(false);
	});

	it("splits WEBAUTHN_TOP_ORIGIN the same way, and keeps its own refusals", () => {
		expect(
			webauthnConfigSchema.parse({
				...VALID,
				topOrigin: "https://partner.example, https://other.example",
			}).topOrigin,
		).toEqual(["https://partner.example", "https://other.example"]);
		expect(
			webauthnConfigSchema.safeParse({ ...VALID, topOrigin: `https://partner.example,${ANDROID}` })
				.success,
		).toBe(false);
	});

	it("leaves any other shape to the schema, which names the type it expected", () => {
		// Only the two spellings are read. Anything else reaches the array
		// schema as it is, so the refusal says "expected array" rather than
		// reporting an empty list the operator never wrote.
		for (const key of ["origin", "topOrigin"] as const) {
			for (const bad of [42, null, {}, true]) {
				const result = webauthnConfigSchema.safeParse({ ...VALID, [key]: bad });
				expect(result.success, `${key}: ${JSON.stringify(bad)}`).toBe(false);
				expect(result.error?.issues[0], `${key}: ${JSON.stringify(bad)}`).toMatchObject({
					code: "invalid_type",
					expected: "array",
					path: [key],
				});
			}
		}
	});

	it("refuses a list entry that is not a string at its index, rather than dropping it", () => {
		// Dropping it would shorten the list the operator wrote and accept the
		// rest — or, for a list of nothing else, refuse it as empty.
		for (const key of ["origin", "topOrigin"] as const) {
			for (const [bad, index] of [
				[[5], 0],
				[["https://a.example", 5], 1],
				[["https://a.example", null], 1],
			] as const) {
				const result = webauthnConfigSchema.safeParse({ ...VALID, [key]: bad });
				expect(result.success, `${key}: ${JSON.stringify(bad)}`).toBe(false);
				expect(result.error?.issues[0], `${key}: ${JSON.stringify(bad)}`).toMatchObject({
					code: "invalid_type",
					expected: "string",
					path: [key, index],
				});
			}
		}
	});

	it("reads an exported-but-empty WEBAUTHN_TOP_ORIGIN as unset: not framed", () => {
		expect(webauthnConfigSchema.parse({ ...VALID, topOrigin: "" }).topOrigin).toBeUndefined();
		// The list spelling keeps its rule: an explicit empty list is refused.
		expect(webauthnConfigSchema.safeParse({ ...VALID, topOrigin: [] }).success).toBe(false);
	});
});

// A composition root parses its HOCON with core's `AppConfigSchema` before
// this package sees it, and `AppConfigSchema` is a strip-mode object: a key
// its `webauthn` section does not name is gone by the time a bootstrap module
// hands `config.webauthn` to `webauthnConfigSchema` (#496). Core cannot
// import this package, so the parity is checked from this side, over the
// whole key tree.
describe("core's AppConfigSchema passes through every key webauthnConfigSchema reads", () => {
	/** Every dotted key path in an object schema, through optional / default / pipe wrappers. */
	const keyPaths = (schema: z.ZodType, prefix = ""): string[] => {
		let inner: z.ZodType = schema;
		for (;;) {
			if (inner instanceof z.ZodOptional || inner instanceof z.ZodNullable) {
				inner = inner.unwrap() as z.ZodType;
			} else if (inner instanceof z.ZodDefault) {
				inner = inner.removeDefault() as z.ZodType;
			} else if (inner instanceof z.ZodPipe) {
				inner = inner.out as z.ZodType;
			} else {
				break;
			}
		}
		if (!(inner instanceof z.ZodObject)) return [];
		return Object.entries(inner.shape).flatMap(([key, value]) => {
			const path = prefix === "" ? key : `${prefix}.${key}`;
			return [path, ...keyPaths(value as z.ZodType, path)];
		});
	};

	it("names the same key tree in both schemas", () => {
		const coreSection = AppConfigSchema.shape.webauthn;
		expect(keyPaths(coreSection).sort()).toEqual(keyPaths(webauthnConfigSchema).sort());
		// Not vacuous: the walk reached the nested rate-limit spec.
		expect(keyPaths(webauthnConfigSchema)).toContain("rateLimit.authenticationOptions.limit");
	});
});
