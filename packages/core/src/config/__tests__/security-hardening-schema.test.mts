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
 * #282 — schema-level hardening of the values an operator supplies:
 *
 *  - `session.secret` carries a 256-bit entropy floor (the JWT signing
 *    secret's floor lives in the keystore builder, per ADR 2026-04-30).
 *  - Durations are positive and bounded, so an empty environment variable
 *    (which HOCON substitutes as `""` and `z.coerce.number()` turns into 0)
 *    fails boot instead of producing a cookie that expires instantly.
 *  - `SameSite=None` requires `Secure`, because every current browser drops
 *    such a cookie outright — a silent, total session failure.
 */
import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import { makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";

type SessionOverrides = Record<string, unknown>;

function parseWithSession(overrides: SessionOverrides) {
	const base = makeValidAppConfig();
	return AppConfigSchema.safeParse({
		...base,
		session: { ...base.session, ...overrides },
	});
}

function issuePaths(result: ReturnType<typeof AppConfigSchema.safeParse>): string[] {
	return result.success ? [] : result.error.issues.map((i) => i.path.join("."));
}

function issueMessages(result: ReturnType<typeof AppConfigSchema.safeParse>): string {
	return result.success ? "" : result.error.issues.map((i) => i.message).join("\n");
}

describe("session.secret entropy floor", () => {
	it("accepts the fixture's baseline secret", () => {
		expect(AppConfigSchema.safeParse(makeValidAppConfig()).success).toBe(true);
	});

	it("rejects a one-character session secret", () => {
		const result = parseWithSession({ secret: "x" });
		expect(result.success).toBe(false);
		expect(issuePaths(result)).toContain("session.secret");
		expect(issueMessages(result)).toMatch(/at least 32 bytes/i);
	});

	it("rejects a short passphrase", () => {
		const result = parseWithSession({ secret: "test-session-secret" });
		expect(result.success).toBe(false);
		expect(issueMessages(result)).toMatch(/at least 32 bytes/i);
	});

	it("rejects a 32-character hex secret — decoded that is only 16 bytes", () => {
		const result = parseWithSession({ secret: "0123456789abcdef0123456789abcdef" });
		expect(result.success).toBe(false);
		expect(issueMessages(result)).toMatch(/at least 32 bytes/i);
	});

	it("accepts a 64-character hex secret", () => {
		const result = parseWithSession({
			secret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		});
		expect(result.success).toBe(true);
	});

	it("names SESSION_SECRET so the operator knows which variable to set", () => {
		expect(issueMessages(parseWithSession({ secret: "x" }))).toContain("SESSION_SECRET");
	});

	it("does not echo the rejected secret back in the error", () => {
		expect(issueMessages(parseWithSession({ secret: "hunter2-secret" }))).not.toContain(
			"hunter2-secret",
		);
	});
});

describe("session cookie durations are positive and bounded", () => {
	it("rejects maxAge = 0 (the shape an empty SESSION_MAX_AGE coerces to)", () => {
		const result = parseWithSession({ maxAge: 0 });
		expect(result.success).toBe(false);
		expect(issuePaths(result)).toContain("session.maxAge");
	});

	it("rejects an empty-string maxAge outright", () => {
		// HOCON substitutes an unset-but-exported env var as "", and
		// `z.coerce.number()` turns that into 0.
		const result = parseWithSession({ maxAge: "" });
		expect(result.success).toBe(false);
		expect(issuePaths(result)).toContain("session.maxAge");
	});

	it("rejects a negative maxAge", () => {
		expect(parseWithSession({ maxAge: -1 }).success).toBe(false);
	});

	it("rejects a non-integer maxAge", () => {
		expect(parseWithSession({ maxAge: 1.5 }).success).toBe(false);
	});

	it("rejects a maxAge beyond one year", () => {
		expect(parseWithSession({ maxAge: 31_536_000_000 + 1 }).success).toBe(false);
	});

	it("accepts a one-year maxAge (the ceiling itself)", () => {
		expect(parseWithSession({ maxAge: 31_536_000_000 }).success).toBe(true);
	});

	it("accepts the ordinary one-hour maxAge", () => {
		expect(parseWithSession({ maxAge: 3_600_000 }).success).toBe(true);
	});
});

describe("token lifetimes are positive and bounded", () => {
	function parseWithOauth(patch: (base: ReturnType<typeof makeValidAppConfig>) => unknown) {
		const base = makeValidAppConfig();
		return AppConfigSchema.safeParse(patch(base));
	}

	it("rejects accessToken.expiresIn = 0", () => {
		const result = parseWithOauth((base) => ({
			...base,
			oauth: { ...base.oauth, accessToken: { expiresIn: 0 } },
		}));
		expect(result.success).toBe(false);
		expect(issuePaths(result)).toContain("oauth.accessToken.expiresIn");
	});

	it("rejects a negative accessToken.expiresIn", () => {
		const result = parseWithOauth((base) => ({
			...base,
			oauth: { ...base.oauth, accessToken: { expiresIn: -1 } },
		}));
		expect(result.success).toBe(false);
	});

	it("rejects refreshToken.expiresIn = 0", () => {
		const result = parseWithOauth((base) => ({
			...base,
			oauth: {
				...base.oauth,
				refreshToken: { ...base.oauth.refreshToken, expiresIn: 0 },
			},
		}));
		expect(result.success).toBe(false);
		expect(issuePaths(result)).toContain("oauth.refreshToken.expiresIn");
	});

	it("accepts the shipped defaults (3600s access, 86400s refresh)", () => {
		expect(AppConfigSchema.safeParse(makeValidAppConfig()).success).toBe(true);
	});
});

describe("login rate-limit window is positive and bounded", () => {
	function parseWithRateLimit(login: Record<string, unknown>) {
		const base = makeValidAppConfig();
		return AppConfigSchema.safeParse({
			...base,
			rateLimit: { ...base.rateLimit, login: { ...base.rateLimit.login, ...login } },
		});
	}

	it("rejects windowMs = 0 — a zero window disables the brute-force guard", () => {
		const result = parseWithRateLimit({ windowMs: 0 });
		expect(result.success).toBe(false);
		expect(issuePaths(result)).toContain("rateLimit.login.windowMs");
	});

	it("rejects limit = 0", () => {
		expect(parseWithRateLimit({ limit: 0 }).success).toBe(false);
	});

	it("accepts the shipped 15-minute / 20-attempt window", () => {
		expect(parseWithRateLimit({ windowMs: 900_000, limit: 20 }).success).toBe(true);
	});
});

describe("SameSite=None requires Secure", () => {
	it("rejects sameSite='none' with secure=false", () => {
		// Chrome, Firefox and Safari all reject `SameSite=None` without
		// `Secure`, so the cookie is never stored and every login silently
		// fails with no server-side signal.
		const result = parseWithSession({
			sameSite: "none",
			secure: false,
			name: "auth.sid", // __Host- has its own (already enforced) rules
		});
		expect(result.success).toBe(false);
		expect(issuePaths(result)).toContain("session.secure");
		expect(issueMessages(result)).toMatch(/SameSite=None/i);
	});

	it("accepts sameSite='none' with secure=true", () => {
		expect(parseWithSession({ sameSite: "none", secure: true }).success).toBe(true);
	});

	it("still accepts sameSite='lax' with secure=false (local HTTP development)", () => {
		expect(parseWithSession({ sameSite: "lax", secure: false, name: "auth.sid" }).success).toBe(
			true,
		);
	});
});
