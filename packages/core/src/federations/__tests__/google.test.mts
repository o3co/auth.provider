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

import type { AppConfig } from "#/config/application.schema.mjs";
import { createGoogleProvider } from "../google.mjs";

const baseConfig = {
	http: { port: 3000, trustProxy: false },
	oauth: {
		jwt: { secret: "secret", kid: "v0", algorithm: "HS256" as const, previousKeys: [] },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {
			session: { enabled: true },
			authorization: { enabled: true },
			refresh_token: { enabled: true },
},
	},
	session: {
		secret: "sess",
		maxAge: 3600000,
		secure: true,
		sameSite: "lax" as const,
		domain: "example.com",
		storage: { type: "redis", redis: { url: "redis://localhost:6379" } },
	},
	rateLimit: {
		login: { windowMs: 60000, limit: 10 },
		token: { windowMs: 60000, limit: 10 },
		authorize: { windowMs: 60000, limit: 10 },
	},
	federations: {
		google: { enabled: true },
	},
	clients: {
		client: { type: "yaml", path: "./config/clients.yaml" },
		user: {
			type: "http",
			path: "./config/users.yaml",
			authenticateUrl: "http://localhost:3001/user/authenticate",
			authenticateByTokenUrl: "http://localhost:3001/user/authenticate/token",
			timeout: 5000,
		},
		code: { type: "redis", endpointUri: "redis://localhost:6379", defaultExpiresIn: 600 },
	},
	endpoints: {
		login: { url: "http://example.com/login" },
		client: { url: "http://example.com" },
		authCallback: { url: "http://example.com/auth/callback" },
	},
	cors: { allowedOrigins: [] },
} satisfies AppConfig;

describe("createGoogleProvider", () => {
	describe("metadata", () => {
		it("has correct name", () => {
			const provider = createGoogleProvider(baseConfig);
			expect(provider.name).toBe("google");
		});

		it("has correct strategyName", () => {
			const provider = createGoogleProvider(baseConfig);
			expect(provider.strategyName).toBe("google");
		});

		it("has correct scope", () => {
			const provider = createGoogleProvider(baseConfig);
			expect(provider.scope).toEqual(["profile", "email"]);
		});

		it("reflects enabled from config", () => {
			const provider = createGoogleProvider(baseConfig);
			expect(provider.enabled).toBe(true);
		});

		it("reflects disabled from config", () => {
			const config: AppConfig = {
				...baseConfig,
				federations: { google: { enabled: false } },
			};
			const provider = createGoogleProvider(config);
			expect(provider.enabled).toBe(false);
		});
	});

	describe("validateRedirect", () => {
		it("accepts a valid https URL on the configured domain", () => {
			const provider = createGoogleProvider(baseConfig);
			const result = provider.validateRedirect("https://example.com/dashboard");
			expect(result.ok).toBe(true);
		});

		it("accepts a valid http URL on the configured domain", () => {
			const provider = createGoogleProvider(baseConfig);
			const result = provider.validateRedirect("http://example.com/page");
			expect(result.ok).toBe(true);
		});

		it("accepts a valid https URL on a subdomain of the configured domain", () => {
			const provider = createGoogleProvider(baseConfig);
			const result = provider.validateRedirect("https://app.example.com/dashboard");
			expect(result.ok).toBe(true);
		});

		it("rejects a URL with ftp scheme", () => {
			const provider = createGoogleProvider(baseConfig);
			const result = provider.validateRedirect("ftp://example.com/file");
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.status).toBe(400);
				expect(result.error).toBe("invalid_redirect");
			}
		});

		it("rejects a URL whose hostname does not match the configured domain", () => {
			const provider = createGoogleProvider(baseConfig);
			const result = provider.validateRedirect("https://evil.com/phish");
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.status).toBe(400);
				expect(result.error).toBe("invalid_redirect");
			}
		});

		it("rejects a URL exceeding 2048 characters", () => {
			const provider = createGoogleProvider(baseConfig);
			const long = `https://example.com/${"a".repeat(2050)}`;
			const result = provider.validateRedirect(long);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.status).toBe(400);
				expect(result.error).toBe("invalid_redirect");
			}
		});

		it("rejects a completely invalid URL", () => {
			const provider = createGoogleProvider(baseConfig);
			const result = provider.validateRedirect("not-a-url");
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.status).toBe(400);
				expect(result.error).toBe("invalid_redirect");
			}
		});

		it("accepts any URL when no domain is configured", () => {
			const config: AppConfig = {
				...baseConfig,
				session: { ...baseConfig.session, domain: null },
			};
			const provider = createGoogleProvider(config);
			const result = provider.validateRedirect("https://anywhere.example.org/path");
			expect(result.ok).toBe(true);
		});

		it("accepts URL when domain config starts with a leading dot", () => {
			const config: AppConfig = {
				...baseConfig,
				session: { ...baseConfig.session, domain: ".example.com" },
			};
			const provider = createGoogleProvider(config);
			const result = provider.validateRedirect("https://app.example.com/page");
			expect(result.ok).toBe(true);
		});
	});

	describe("resolveCallbackRedirect", () => {
		it("combines authCallbackUrl with redirectTo when both are available", () => {
			const provider = createGoogleProvider(baseConfig);
			const result = provider.resolveCallbackRedirect({ redirectTo: "https://example.com/home" });
			expect(result.ok).toBe(true);
			if (result.ok) {
				expect(result.value).toBe(
					`http://example.com/auth/callback?redirect_to=${encodeURIComponent("https://example.com/home")}`,
				);
			}
		});

		it("falls back to clientUrl when redirectTo is absent", () => {
			const provider = createGoogleProvider(baseConfig);
			const result = provider.resolveCallbackRedirect({});
			expect(result.ok).toBe(true);
			if (result.ok) {
				expect(result.value).toBe("http://example.com");
			}
		});

		it("falls back to clientUrl when redirectTo is absent even if authCallbackUrl is set", () => {
			const provider = createGoogleProvider(baseConfig);
			const result = provider.resolveCallbackRedirect({ redirectTo: undefined });
			expect(result.ok).toBe(true);
			if (result.ok) {
				expect(result.value).toBe("http://example.com");
			}
		});

		it("returns error when clientUrl is not configured and no redirectTo", () => {
			const config: AppConfig = {
				...baseConfig,
				endpoints: {
					...baseConfig.endpoints,
					client: { url: undefined },
					authCallback: { url: undefined },
				},
			};
			const provider = createGoogleProvider(config);
			const result = provider.resolveCallbackRedirect({});
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.status).toBe(500);
			}
		});
	});
});
