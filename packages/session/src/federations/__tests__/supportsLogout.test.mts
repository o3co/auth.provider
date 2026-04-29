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
import {
	type EndSessionRequest,
	type EndSessionResult,
	type FederationProvider,
	type SupportsLogout,
	supportsLogout,
} from "#/federations/types.mjs";

function makeBaseProvider(name: string): FederationProvider {
	return {
		name,
		scope: [],
		buildAuthorizationUrl: () => new URL("https://example.com/authorize"),
		exchangeCode: async () => ({ issuer: "https://example.com", sub: "test-sub", expiresAt: null }),
	};
}

function makeLogoutProvider(name: string, endpoint: string): FederationProvider & SupportsLogout {
	return {
		...makeBaseProvider(name),
		async endSession(req: EndSessionRequest): Promise<EndSessionResult> {
			const url = new URL(endpoint);
			if (req.idTokenHint) url.searchParams.set("id_token_hint", req.idTokenHint);
			if (req.postLogoutRedirectUri)
				url.searchParams.set("post_logout_redirect_uri", req.postLogoutRedirectUri);
			if (req.state) url.searchParams.set("state", req.state);
			return { url, method: "GET" };
		},
	};
}

describe("supportsLogout()", () => {
	it("returns true for a provider implementing SupportsLogout", () => {
		const p = makeLogoutProvider("myidp", "https://myidp.example/logout");
		expect(supportsLogout(p)).toBe(true);
	});

	it("returns false for a provider without endSession", () => {
		const p = makeBaseProvider("plain");
		expect(supportsLogout(p)).toBe(false);
	});

	it("narrows the type so endSession is callable without cast", async () => {
		const p: FederationProvider = makeLogoutProvider("myidp", "https://myidp.example/logout");
		if (supportsLogout(p)) {
			// Inside this branch, TypeScript narrows `p` to `FederationProviderBase & SupportsLogout`.
			const result = await p.endSession({ idTokenHint: "abc" });
			expect(result.method).toBe("GET");
		} else {
			throw new Error("expected supportsLogout to narrow to true");
		}
	});

	it("returns false for undefined (no throw)", () => {
		expect(supportsLogout(undefined)).toBe(false);
	});

	it("returns false for null (no throw)", () => {
		expect(supportsLogout(null)).toBe(false);
	});
});

describe("EndSessionResult URL construction (reference implementation behaviour)", () => {
	it("encodes all three optional parameters when present", async () => {
		const p = makeLogoutProvider("myidp", "https://myidp.example/logout");
		const { url, method } = await p.endSession({
			idTokenHint: "id-abc",
			postLogoutRedirectUri: "https://app.example/after-logout",
			state: "nonce-1",
		});
		expect(method).toBe("GET");
		expect(url.searchParams.get("id_token_hint")).toBe("id-abc");
		expect(url.searchParams.get("post_logout_redirect_uri")).toBe(
			"https://app.example/after-logout",
		);
		expect(url.searchParams.get("state")).toBe("nonce-1");
	});

	it("omits parameters that are not provided", async () => {
		const p = makeLogoutProvider("myidp", "https://myidp.example/logout");
		const { url } = await p.endSession({ idTokenHint: "only-hint" });
		expect(url.searchParams.get("id_token_hint")).toBe("only-hint");
		expect(url.searchParams.has("post_logout_redirect_uri")).toBe(false);
		expect(url.searchParams.has("state")).toBe(false);
	});
});

describe("fixture module (packages/session/src/federations/__tests__/fixtures.mts)", () => {
	it("exports createTestBaseProvider and createTestLogoutProvider", async () => {
		const fixtures = await import("./fixtures.mjs");
		expect(typeof fixtures.createTestBaseProvider).toBe("function");
		expect(typeof fixtures.createTestLogoutProvider).toBe("function");
	});

	it("createTestLogoutProvider returns a provider that passes supportsLogout()", async () => {
		const { createTestLogoutProvider } = await import("./fixtures.mjs");
		const p = createTestLogoutProvider({
			name: "fixture-idp",
			endSessionEndpoint: "https://fixture.example/oidc/logout",
		});
		expect(supportsLogout(p)).toBe(true);
	});

	it("createTestBaseProvider returns a provider that fails supportsLogout()", async () => {
		const { createTestBaseProvider } = await import("./fixtures.mjs");
		const p = createTestBaseProvider("fixture-plain");
		expect(supportsLogout(p)).toBe(false);
	});
});
