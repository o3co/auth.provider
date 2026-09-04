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

import { describe, expect, it } from "vitest";
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

		it("allowCredentialsForKnownUser must be a boolean", () => {
			expect(
				webauthnConfigSchema.safeParse({ ...VALID, allowCredentialsForKnownUser: "true" }).success,
			).toBe(false);
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
