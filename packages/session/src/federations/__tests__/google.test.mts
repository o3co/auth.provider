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

import type { PassportStatic } from "passport";
import { describe, expect, it, vi } from "vitest";
import { createGoogleProvider } from "#/federations/google.mjs";

const baseConfig = {
	name: "google",
	clientId: "gid",
	clientSecret: "gsecret",
	callbackURL: "http://localhost/callback",
	sessionDomain: ".example.com",
	authCallbackUrl: "/auth/callback",
	clientUrl: "http://localhost:3001",
};

describe("createGoogleProvider", () => {
	it("returns a provider with the configured name", () => {
		const provider = createGoogleProvider(baseConfig);
		expect(provider.name).toBe("google");
	});

	it("validates redirect URL against session domain", () => {
		const provider = createGoogleProvider(baseConfig);
		const result = provider.validateRedirect("https://app.example.com/callback");
		expect(result.ok).toBe(true);
	});

	it("rejects redirect URL from different domain", () => {
		const provider = createGoogleProvider(baseConfig);
		const result = provider.validateRedirect("https://evil.com/callback");
		expect(result.ok).toBe(false);
	});

	it("resolves callback redirect with redirectTo", () => {
		const provider = createGoogleProvider(baseConfig);
		const result = provider.resolveCallbackRedirect({
			redirectTo: "https://app.example.com/dashboard",
		});
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value).toContain("/auth/callback");
			expect(result.value).toContain("redirect_to=");
		}
	});

	it("returns misconfiguration error when clientUrl and authCallbackUrl are undefined", () => {
		const configWithoutWebEndpoints = {
			...baseConfig,
			authCallbackUrl: undefined,
			clientUrl: undefined,
		};
		const provider = createGoogleProvider(configWithoutWebEndpoints);
		const result = provider.resolveCallbackRedirect({});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error).toBe("misconfiguration");
		}
	});

	it("returns misconfiguration error when redirectTo is set but authCallbackUrl is undefined", () => {
		const configWithClientOnly = {
			...baseConfig,
			authCallbackUrl: undefined,
		};
		const provider = createGoogleProvider(configWithClientOnly);
		const result = provider.resolveCallbackRedirect({
			redirectTo: "https://app.example.com/dashboard",
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error).toBe("misconfiguration");
			expect(result.errorDescription).toContain("authCallback");
		}
	});

	it("falls back to client URL when authCallbackUrl is undefined and no redirectTo", () => {
		const configWithClientOnly = {
			...baseConfig,
			authCallbackUrl: undefined,
		};
		const provider = createGoogleProvider(configWithClientOnly);
		const result = provider.resolveCallbackRedirect({});
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value).toBe("http://localhost:3001");
		}
	});
});

describe("setupPassportStrategy", () => {
	it("registers passport-google-oauth20 strategy under provider.name", async () => {
		const mockPassport = { use: vi.fn() } as unknown as PassportStatic;
		const verifyUser = vi.fn(async () => null);
		const provider = createGoogleProvider(baseConfig);
		await provider.setupPassportStrategy(mockPassport, { verifyUser });
		expect(mockPassport.use).toHaveBeenCalledWith("google", expect.any(Object));
	});

	it("verify callback builds externalId as 'google:' + profile.id", async () => {
		const mockPassport = { use: vi.fn() } as unknown as PassportStatic;
		const verifyUser = vi.fn(async () => null);
		const provider = createGoogleProvider(baseConfig);
		await provider.setupPassportStrategy(mockPassport, { verifyUser });
		// Extract the verify callback passed to the GoogleStrategy constructor
		const strategyInstance = (mockPassport.use as ReturnType<typeof vi.fn>).mock.calls[0][1];
		const verifyCallback = strategyInstance._verify ?? strategyInstance.verify;
		// Invoke it with a mock profile
		const done = vi.fn();
		await verifyCallback("at", "rt", { id: "12345" }, done);
		expect(verifyUser).toHaveBeenCalledWith("google:12345");
	});

	it("uses config.name as the passport strategy identifier for multi-tenant", async () => {
		const mockPassport = { use: vi.fn() } as unknown as PassportStatic;
		const provider = createGoogleProvider({
			...baseConfig,
			name: "google-work",
		});
		await provider.setupPassportStrategy(mockPassport, { verifyUser: async () => null });
		expect(mockPassport.use).toHaveBeenCalledWith("google-work", expect.any(Object));
	});
});

describe("createGoogleProvider validation", () => {
	it("throws when clientId is missing", () => {
		expect(() => createGoogleProvider({ ...baseConfig, clientId: "" })).toThrow(/clientId/i);
	});

	it("throws when clientSecret is missing", () => {
		expect(() => createGoogleProvider({ ...baseConfig, clientSecret: "" })).toThrow(
			/clientSecret/i,
		);
	});

	it("throws when callbackURL is missing", () => {
		expect(() => createGoogleProvider({ ...baseConfig, callbackURL: "" })).toThrow(/callbackURL/i);
	});
});
