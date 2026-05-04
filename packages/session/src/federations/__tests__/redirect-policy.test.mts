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
import { createFederationRedirectPolicy } from "../redirect-policy.mjs";

const baseConfig = {
	sessionDomain: "example.com",
	authCallbackUrl: "https://app.example.com/auth/callback",
	clientUrl: "https://app.example.com",
};

describe("createFederationRedirectPolicy — validateRedirect", () => {
	it("accepts a valid URL on the session domain", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		const result = policy.validateRedirect("https://example.com/dashboard");
		expect(result.ok).toBe(true);
	});

	it("accepts a subdomain of the session domain", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		const result = policy.validateRedirect("https://sub.example.com/page");
		expect(result.ok).toBe(true);
	});

	it("rejects a URL on a different domain", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		const result = policy.validateRedirect("https://evil.com/steal");
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.status).toBe(400);
			expect(result.error).toBe("invalid_redirect");
		}
	});

	it("rejects a URL that exceeds 2048 characters", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		// "https://example.com/" = 21 chars; pad to total > 2048
		const longUrl = `https://example.com/${"x".repeat(2100)}`;
		const result = policy.validateRedirect(longUrl);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.status).toBe(400);
			expect(result.error).toBe("invalid_redirect");
		}
	});

	it("rejects a non-http/https scheme", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		const result = policy.validateRedirect("ftp://example.com/file");
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.status).toBe(400);
			expect(result.error).toBe("invalid_redirect");
		}
	});

	it("accepts any domain when sessionDomain is not configured", () => {
		const policy = createFederationRedirectPolicy({
			authCallbackUrl: "https://app.example.com/auth/callback",
			clientUrl: "https://app.example.com",
		});
		const result = policy.validateRedirect("https://anywhere.example.org/page");
		expect(result.ok).toBe(true);
	});
});

describe("createFederationRedirectPolicy — resolveCallbackRedirect", () => {
	it("returns authCallbackUrl?redirect_to=<encoded> when session has redirectTo", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		const redirectTo = "https://example.com/dashboard";
		const result = policy.resolveCallbackRedirect({ redirectTo });
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value).toBe(
				`https://app.example.com/auth/callback?redirect_to=${encodeURIComponent(redirectTo)}`,
			);
		}
	});

	it("returns clientUrl fallback when session has no redirectTo", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		const result = policy.resolveCallbackRedirect({});
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value).toBe("https://app.example.com");
		}
	});

	it("returns misconfiguration error when redirectTo present but authCallbackUrl absent", () => {
		const policy = createFederationRedirectPolicy({
			clientUrl: "https://app.example.com",
		});
		const result = policy.resolveCallbackRedirect({ redirectTo: "https://example.com/x" });
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.status).toBe(500);
			expect(result.error).toBe("misconfiguration");
		}
	});

	it("returns misconfiguration error when no redirectTo and clientUrl absent", () => {
		const policy = createFederationRedirectPolicy({
			authCallbackUrl: "https://app.example.com/auth/callback",
		});
		const result = policy.resolveCallbackRedirect({});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.status).toBe(500);
			expect(result.error).toBe("misconfiguration");
		}
	});
});

describe("createFederationRedirectPolicy — return value is frozen", () => {
	it("returned policy is Object.frozen", () => {
		const policy = createFederationRedirectPolicy(baseConfig);
		expect(Object.isFrozen(policy)).toBe(true);
	});
});
