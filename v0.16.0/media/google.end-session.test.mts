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
 * `endSession()`: Google publishes no end-session endpoint, so without a
 * configured one the adapter answers with the `postLogoutRedirectUri` it was
 * handed — which its caller has already held to the client's registered list
 * (core's `EndSessionRequest`) — or with Google's own logout page.
 *
 * No library is involved: the adapter builds the URL itself.
 */

import { describe, expect, it } from "vitest";
import { createGoogleProvider } from "#/google.mjs";

const baseConfig = {
	clientId: "client-id",
	clientSecret: "client-secret",
	callbackURL: "https://app.example.com/session/oauth/federation/google/callback",
};

describe("Google endSession()", () => {
	it("uses a configured end-session endpoint, with the hint, the redirect URI and state", async () => {
		const p = createGoogleProvider({
			...baseConfig,
			endSessionEndpoint: "https://idp-logout.example/end",
		});
		const { url, method } = await p.endSession({
			idTokenHint: "id-token",
			postLogoutRedirectUri: "https://rp.example/signed-out",
			state: "st",
		});
		expect(method).toBe("GET");
		expect(`${url.origin}${url.pathname}`).toBe("https://idp-logout.example/end");
		expect(url.searchParams.get("id_token_hint")).toBe("id-token");
		expect(url.searchParams.get("post_logout_redirect_uri")).toBe("https://rp.example/signed-out");
		expect(url.searchParams.get("state")).toBe("st");
	});

	it("redirects straight to the postLogoutRedirectUri it is handed when no endpoint is configured", async () => {
		const p = createGoogleProvider(baseConfig);
		const { url } = await p.endSession({
			postLogoutRedirectUri: "https://rp.example/signed-out",
			state: "st",
		});
		expect(url.href).toBe("https://rp.example/signed-out?state=st");
	});

	it("sends the browser to Google's own logout page when handed no postLogoutRedirectUri", async () => {
		const p = createGoogleProvider(baseConfig);
		const { url } = await p.endSession({ state: "st" });
		expect(url.href).toBe("https://accounts.google.com/Logout?state=st");
	});

	it("refuses a postLogoutRedirectUri that is not a URL without repeating it", async () => {
		// The value reaches a log line as the error's `detail`, which keeps a
		// message's text; the adapter names what was wrong and quotes nothing
		// it was handed.
		const p = createGoogleProvider(baseConfig);
		const handed = '%%bogus "\r\ninjected-line';
		const refusal = await p.endSession({ postLogoutRedirectUri: handed }).then(
			() => undefined,
			(error: unknown) => error,
		);
		expect(refusal).toBeInstanceOf(Error);
		expect((refusal as Error).message).toMatch(/invalid postLogoutRedirectUri/);
		expect((refusal as Error).message).not.toContain("injected-line");
		expect((refusal as Error).message).not.toContain("%%bogus");
	});
});
