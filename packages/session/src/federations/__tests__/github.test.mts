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
import { createGithubProvider } from "#/federations/github.mjs";
import type { FederationProfile } from "#/federations/types.mjs";
import { supportsClaimMapping, supportsLogout, supportsRefresh } from "#/federations/types.mjs";

const baseConfig = {
	name: "github",
	clientId: "ghid",
	clientSecret: "ghsecret",
	callbackURL: "http://localhost/callback",
	sessionDomain: ".example.com",
	authCallbackUrl: "/auth/callback",
	clientUrl: "http://localhost:3001",
};

describe("createGithubProvider", () => {
	it("returns a provider with the configured name", () => {
		const provider = createGithubProvider(baseConfig);
		expect(provider.name).toBe("github");
	});

	it("returns scope === ['read:user', 'user:email']", () => {
		const provider = createGithubProvider(baseConfig);
		expect(provider.scope).toEqual(["read:user", "user:email"]);
	});

	it("validates redirect URL against session domain", () => {
		const provider = createGithubProvider(baseConfig);
		const result = provider.validateRedirect("https://app.example.com/callback");
		expect(result.ok).toBe(true);
	});

	it("rejects redirect URL from different domain", () => {
		const provider = createGithubProvider(baseConfig);
		const result = provider.validateRedirect("https://evil.com/callback");
		expect(result.ok).toBe(false);
	});

	it("resolves callback redirect with redirectTo", () => {
		const provider = createGithubProvider(baseConfig);
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
		const provider = createGithubProvider(configWithoutWebEndpoints);
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
		const provider = createGithubProvider(configWithClientOnly);
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
		const provider = createGithubProvider(configWithClientOnly);
		const result = provider.resolveCallbackRedirect({});
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value).toBe("http://localhost:3001");
		}
	});
});

describe("setupPassportStrategy", () => {
	it("registers passport-github2 strategy under provider.name", async () => {
		const mockPassport = { use: vi.fn() } as unknown as PassportStatic;
		const verifyUser = vi.fn(async () => null);
		const provider = createGithubProvider(baseConfig);
		await provider.setupPassportStrategy(mockPassport, { verifyUser });
		expect(mockPassport.use).toHaveBeenCalledWith("github", expect.any(Object));
	});

	it("verify callback builds externalId as 'github:' + profile.id", async () => {
		const mockPassport = { use: vi.fn() } as unknown as PassportStatic;
		const verifyUser = vi.fn(async () => null);
		const provider = createGithubProvider(baseConfig);
		await provider.setupPassportStrategy(mockPassport, { verifyUser });
		// Extract the verify callback passed to the GithubStrategy constructor
		const strategyInstance = (mockPassport.use as ReturnType<typeof vi.fn>).mock.calls[0][1];
		const verifyCallback = strategyInstance._verify ?? strategyInstance.verify;
		// Invoke it with a mock profile
		const done = vi.fn();
		await verifyCallback("at", "rt", { id: "99999" }, done);
		expect(verifyUser).toHaveBeenCalledWith("github:99999");
	});

	it("uses config.name as the passport strategy identifier for multi-tenant", async () => {
		const mockPassport = { use: vi.fn() } as unknown as PassportStatic;
		const provider = createGithubProvider({
			...baseConfig,
			name: "github-enterprise",
		});
		await provider.setupPassportStrategy(mockPassport, { verifyUser: async () => null });
		expect(mockPassport.use).toHaveBeenCalledWith("github-enterprise", expect.any(Object));
	});

	it("uses ctx.pathResolver when provided to resolve passport-github2", async () => {
		const mockPassport = { use: vi.fn() } as unknown as PassportStatic;
		const provider = createGithubProvider(baseConfig);
		// pathResolver records what spec was requested and returns the real module path
		// so the dynamic import actually succeeds in this test environment.
		const resolved: string[] = [];
		const pathResolver = (spec: string) => {
			resolved.push(spec);
			return spec; // fall through to real module resolution
		};
		await provider.setupPassportStrategy(mockPassport, {
			verifyUser: async () => null,
			pathResolver,
		});
		expect(resolved).toContain("passport-github2");
	});

	it.skip("throws a clear error when passport-github2 is not installed (TODO: test via dynamic import mock — verify manually with package uninstalled)", () => {
		// Manual verification: uninstall passport-github2 and call setupPassportStrategy.
		// Expect: Error matching /GitHub federation requires passport-github2/i
		// with the original module-not-found error as `cause`.
	});
});

describe("createGithubProvider validation", () => {
	it("throws when clientId is missing", () => {
		expect(() => createGithubProvider({ ...baseConfig, clientId: "" })).toThrow(/clientId/i);
	});

	it("throws when clientSecret is missing", () => {
		expect(() => createGithubProvider({ ...baseConfig, clientSecret: "" })).toThrow(
			/clientSecret/i,
		);
	});

	it("throws when callbackURL is missing", () => {
		expect(() => createGithubProvider({ ...baseConfig, callbackURL: "" })).toThrow(/callbackURL/i);
	});
});

describe("GitHub provider capabilities", () => {
	const base = {
		name: "github",
		clientId: "cid",
		clientSecret: "csec",
		callbackURL: "https://example.com/cb",
	};

	it("implements mapClaims and endSession; does NOT implement refresh", () => {
		const p = createGithubProvider(base);
		expect(supportsClaimMapping(p)).toBe(true);
		expect(supportsLogout(p)).toBe(true);
		expect(supportsRefresh(p)).toBe(false);
	});

	describe("mapClaims", () => {
		it("maps profile fields (without fetching /user/emails)", async () => {
			const p = createGithubProvider(base);
			if (!supportsClaimMapping(p)) throw new Error("expected claim mapping");
			const profile: FederationProfile = {
				id: "gh-42",
				raw: {
					username: "alice",
					displayName: "Alice Dev",
					emails: [{ value: "primary@x.com" }],
					photos: [{ value: "https://avatars.githubusercontent.com/u/42" }],
				},
			};
			expect(p.mapClaims(profile)).toEqual({
				email: "primary@x.com",
				name: "Alice Dev",
				picture: "https://avatars.githubusercontent.com/u/42",
			});
		});

		it("omits email when passport profile exposes none (caller must fetchGithubPrimaryEmail separately)", () => {
			const p = createGithubProvider(base);
			if (!supportsClaimMapping(p)) throw new Error("expected claim mapping");
			const profile: FederationProfile = {
				id: "gh",
				raw: { displayName: "Anon" },
			};
			expect(p.mapClaims(profile)).toEqual({ name: "Anon" });
		});
	});

	describe("endSession", () => {
		it("returns a no-op-ish GET URL pointing at the post_logout_redirect_uri directly (GitHub has no end-session endpoint)", async () => {
			const p = createGithubProvider(base);
			if (!supportsLogout(p)) throw new Error("expected logout capability");
			const result = await p.endSession({
				postLogoutRedirectUri: "https://rp/done",
				state: "abc",
			});
			expect(result.method).toBe("GET");
			expect(result.url.href).toContain("https://rp/done");
			expect(result.url.searchParams.get("state")).toBe("abc");
		});
	});
});
