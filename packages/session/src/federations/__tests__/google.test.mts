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

import type { AppConfig } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { createGoogleProvider } from "#/federations/google.mjs";

const baseConfig = {
	federations: {
		google: {
			enabled: true,
			clientId: "gid",
			clientSecret: "gsecret",
			callbackURL: "http://localhost/callback",
		},
	},
	session: { domain: ".example.com" },
	endpoints: {
		login: { url: "/login" },
		client: { url: "http://localhost:3001" },
		authCallback: { url: "/auth/callback" },
	},
} as unknown as AppConfig;

describe("createGoogleProvider", () => {
	it("returns a provider with name 'google'", () => {
		const provider = createGoogleProvider(baseConfig);
		expect(provider.name).toBe("google");
		expect(provider.strategyName).toBe("google");
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

	it("returns misconfiguration error when endpoints.client and endpoints.authCallback are undefined", () => {
		const configWithoutWebEndpoints = {
			...baseConfig,
			endpoints: {
				login: { url: "/login" },
			},
		} as unknown as AppConfig;
		const provider = createGoogleProvider(configWithoutWebEndpoints);
		const result = provider.resolveCallbackRedirect({});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error).toBe("misconfiguration");
		}
	});

	it("falls back to client URL when authCallback is undefined and no redirectTo", () => {
		const configWithClient = {
			...baseConfig,
			endpoints: {
				login: { url: "/login" },
				client: { url: "http://localhost:3001" },
			},
		} as unknown as AppConfig;
		const provider = createGoogleProvider(configWithClient);
		const result = provider.resolveCallbackRedirect({});
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value).toBe("http://localhost:3001");
		}
	});
});
