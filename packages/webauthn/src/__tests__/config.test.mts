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
describe("webauthnConfigSchema (spec §2.4.1)", () => {
	it("accepts minimum valid config with all required fields", () => {
		const parsed = webauthnConfigSchema.parse({
			rpId: "example.com",
			rpName: "Example App",
			origin: ["https://example.com"],
			// S11: attestationPreference = "none" is the dogfood-friendly baseline.
			// In production this comes from reference.conf; tests supply it explicitly
			// per ADR 2026-04-30 (no schema-side defaults).
			attestationPreference: "none",
			userVerification: "preferred",
			challengeTtlMs: 120_000,
		});
		expect(parsed.attestationPreference).toBe("none"); // S11 default value
		expect(parsed.userVerification).toBe("preferred");
		expect(parsed.challengeTtlMs).toBe(120_000); // mobile-network safe baseline
	});

	it("rejects missing rpId", () => {
		expect(
			webauthnConfigSchema.safeParse({
				rpName: "x",
				origin: ["https://x"],
				attestationPreference: "none",
				userVerification: "preferred",
				challengeTtlMs: 120_000,
			}).success,
		).toBe(false);
	});

	it("origin must be non-empty array", () => {
		expect(
			webauthnConfigSchema.safeParse({
				rpId: "x",
				rpName: "x",
				origin: [],
				attestationPreference: "none",
				userVerification: "preferred",
				challengeTtlMs: 120_000,
			}).success,
		).toBe(false);
	});

	it("attestationPreference enum is constrained", () => {
		expect(
			webauthnConfigSchema.safeParse({
				rpId: "x",
				rpName: "x",
				origin: ["https://x"],
				attestationPreference: "bogus",
				userVerification: "preferred",
				challengeTtlMs: 120_000,
			}).success,
		).toBe(false);
	});

	// Wave 1 post-merge audit M-1 + follow-up review I2:
	// URL-parse-based origin gate must reject textual-prefix bypasses.
	describe("origin secure-context gate (M-1 / I2)", () => {
		const okBase = {
			rpId: "x",
			rpName: "x",
			attestationPreference: "none" as const,
			userVerification: "preferred" as const,
			challengeTtlMs: 120_000,
		};
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
});
