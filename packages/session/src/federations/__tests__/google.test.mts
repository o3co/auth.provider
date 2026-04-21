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
import type { FederationProfile } from "#/federations/types.mjs";
import { supportsClaimMapping, supportsLogout, supportsRefresh } from "#/federations/types.mjs";

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
		// Invoke it with a mock profile — passReqToCallback:true means req is the first arg
		// arity-6: req, accessToken, refreshToken, params, profile, done
		const done = vi.fn();
		const reqStub = { session: {} } as unknown as import("express").Request;
		await verifyCallback(reqStub, "at", "rt", {}, { id: "12345" }, done);
		expect(verifyUser).toHaveBeenCalledWith("google:12345");
	});

	it("verify callback passes id_token and expires_in from params to FederationProfile", async () => {
		const mockPassport = { use: vi.fn() } as unknown as PassportStatic;
		const onFederationCallback = vi.fn(
			async ({ done }: { done: (err: Error | null, user: unknown) => void }) => {
				done(null, { id: "u1" });
			},
		);
		const verifyUser = vi.fn(async () => null);
		const provider = createGoogleProvider(baseConfig);
		await provider.setupPassportStrategy(mockPassport, { verifyUser, onFederationCallback });
		const strategyInstance = (mockPassport.use as ReturnType<typeof vi.fn>).mock.calls[0][1];
		const verifyCallback = strategyInstance._verify ?? strategyInstance.verify;
		const done = vi.fn();
		const reqStub = { session: {} } as unknown as import("express").Request;
		// arity-6: params carries id_token and expires_in
		await verifyCallback(
			reqStub,
			"access-token",
			"refresh-token",
			{ id_token: "google-id-token", expires_in: 7200 },
			{ id: "gid-123" },
			done,
		);
		expect(onFederationCallback).toHaveBeenCalledTimes(1);
		const callArg = (onFederationCallback as ReturnType<typeof vi.fn>).mock.calls[0][0] as {
			profile: import("#/federations/types.mjs").FederationProfile;
		};
		expect(callArg.profile.idToken).toBe("google-id-token");
		expect(callArg.profile.expiresIn).toBe(7200);
		expect(callArg.profile.accessToken).toBe("access-token");
		expect(callArg.profile.refreshToken).toBe("refresh-token");
	});

	it("strategy has authorizationParams that always includes access_type=offline", async () => {
		const mockPassport = { use: vi.fn() } as unknown as PassportStatic;
		const provider = createGoogleProvider(baseConfig);
		await provider.setupPassportStrategy(mockPassport, { verifyUser: async () => null });
		const strategyInstance = (mockPassport.use as ReturnType<typeof vi.fn>).mock
			.calls[0][1] as unknown as {
			authorizationParams(opts: Record<string, unknown>): Record<string, unknown>;
		};
		const params = strategyInstance.authorizationParams({});
		expect(params).toMatchObject({ access_type: "offline" });
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

	it("uses ctx.pathResolver when provided to resolve passport-google-oauth20", async () => {
		const mockPassport = { use: vi.fn() } as unknown as PassportStatic;
		const provider = createGoogleProvider(baseConfig);
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
		expect(resolved).toContain("passport-google-oauth20");
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

describe("Google provider capabilities", () => {
	const capConfig = {
		name: "google",
		clientId: "cid",
		clientSecret: "csec",
		callbackURL: "https://example.com/cb",
	};

	it("implements all three capabilities", () => {
		const p = createGoogleProvider(capConfig);
		expect(supportsClaimMapping(p)).toBe(true);
		expect(supportsRefresh(p)).toBe(true);
		expect(supportsLogout(p)).toBe(true);
	});

	describe("mapClaims", () => {
		const p = createGoogleProvider(capConfig);
		it("extracts email + name + picture from google profile", () => {
			if (!supportsClaimMapping(p)) throw new Error("expected claim mapping");
			const profile: FederationProfile = {
				id: "gid-123",
				raw: {
					emails: [{ value: "alice@example.com", verified: true }],
					displayName: "Alice",
					photos: [{ value: "https://lh.com/p.png" }],
					_json: { email: "alice@example.com", email_verified: true, hd: "example.com" },
				},
			};
			expect(p.mapClaims(profile)).toEqual({
				email: "alice@example.com",
				emailVerified: true,
				name: "Alice",
				picture: "https://lh.com/p.png",
				hd: "example.com",
			});
		});

		it("returns empty claims when fields are absent", () => {
			if (!supportsClaimMapping(p)) throw new Error("expected claim mapping");
			const profile: FederationProfile = { id: "gid", raw: {} };
			expect(p.mapClaims(profile)).toEqual({});
		});
	});

	describe("refreshFederationToken", () => {
		it("exchanges refresh_token for a new access_token via Google token endpoint", async () => {
			const fetchMock = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				async json() {
					return {
						access_token: "new-at",
						expires_in: 3600,
						token_type: "Bearer",
						id_token: "new-id",
					};
				},
			});
			const p = createGoogleProvider({
				...capConfig,
				_fetch: fetchMock as unknown as typeof fetch,
			});
			if (!supportsRefresh(p)) throw new Error("expected refresh capability");
			const result = await p.refreshFederationToken("old-rt");
			expect(result.accessToken).toBe("new-at");
			expect(result.idToken).toBe("new-id");
			expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now() + 3500_000);
			expect(fetchMock).toHaveBeenCalledTimes(1);
			const firstCall = fetchMock.mock.calls[0];
			if (!firstCall) throw new Error("expected fetch to be called");
			const [url, init] = firstCall;
			expect(url).toBe("https://oauth2.googleapis.com/token");
			expect((init as RequestInit).method).toBe("POST");
			expect((init as RequestInit).body).toContain("refresh_token=old-rt");
			expect((init as RequestInit).body).toContain("grant_type=refresh_token");
		});

		it("throws invalid_grant-shaped Error when Google rejects the refresh_token", async () => {
			const fetchMock = vi.fn().mockResolvedValue({
				ok: false,
				status: 400,
				async json() {
					return { error: "invalid_grant", error_description: "Token revoked" };
				},
			});
			const p = createGoogleProvider({
				...capConfig,
				_fetch: fetchMock as unknown as typeof fetch,
			});
			if (!supportsRefresh(p)) throw new Error("expected refresh capability");
			await expect(p.refreshFederationToken("rt")).rejects.toThrow(/invalid_grant/);
		});

		it("throws transient-shaped Error on 5xx (caller returns 503 in F-6)", async () => {
			const fetchMock = vi.fn().mockResolvedValue({
				ok: false,
				status: 503,
				async json() {
					return {};
				},
			});
			const p = createGoogleProvider({
				...capConfig,
				_fetch: fetchMock as unknown as typeof fetch,
			});
			if (!supportsRefresh(p)) throw new Error("expected refresh capability");
			await expect(p.refreshFederationToken("rt")).rejects.toThrow(/temporarily_unavailable/);
		});
	});

	describe("endSession", () => {
		it("without endSessionEndpoint configured: redirects to postLogoutRedirectUri directly", async () => {
			const p = createGoogleProvider(capConfig);
			if (!supportsLogout(p)) throw new Error("expected logout capability");
			const { url, method } = await p.endSession({
				postLogoutRedirectUri: "https://rp/logout-done",
				state: "s1",
			});
			expect(method).toBe("GET");
			expect(url.href).toContain("https://rp/logout-done");
			expect(url.searchParams.get("state")).toBe("s1");
		});

		it("without endSessionEndpoint and no postLogoutRedirectUri: falls back to accounts.google.com/Logout", async () => {
			const p = createGoogleProvider(capConfig);
			if (!supportsLogout(p)) throw new Error("expected logout capability");
			const { url, method } = await p.endSession({});
			expect(method).toBe("GET");
			expect(url.hostname).toBe("accounts.google.com");
			expect(url.pathname.endsWith("/Logout")).toBe(true);
		});

		it("with endSessionEndpoint configured: uses it and attaches all params", async () => {
			const p = createGoogleProvider({
				...capConfig,
				endSessionEndpoint: "https://custom-logout.example.com/end",
			});
			if (!supportsLogout(p)) throw new Error("expected logout capability");
			const { url, method } = await p.endSession({
				idTokenHint: "idt",
				postLogoutRedirectUri: "https://rp/done",
				state: "s2",
			});
			expect(method).toBe("GET");
			expect(url.origin).toBe("https://custom-logout.example.com");
			expect(url.pathname).toBe("/end");
			expect(url.searchParams.get("id_token_hint")).toBe("idt");
			expect(url.searchParams.get("post_logout_redirect_uri")).toBe("https://rp/done");
			expect(url.searchParams.get("state")).toBe("s2");
		});
	});
});
