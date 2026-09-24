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
 * The fake GitHub is held to what GitHub does where a client could come to
 * depend on the difference. A fake laxer than GitHub lets the adapter pass
 * against it and fail against GitHub — which is how a mocked library once
 * hid that no GitHub login could succeed.
 */

import { describe, expect, it } from "vitest";
import { createGithubProvider } from "../github.mjs";
import { ACCESS_TOKEN, createFakeGithub, GITHUB } from "./fake-github.mjs";

const tokenRequest = (accept?: string): RequestInit => ({
	method: "POST",
	headers: { "content-type": "application/x-www-form-urlencoded", ...(accept ? { accept } : {}) },
	body: "grant_type=authorization_code&code=c",
});

describe("the fake GitHub answers as GitHub does", () => {
	it("answers the token endpoint form-encoded unless Accept asks for JSON", async () => {
		const github = createFakeGithub();

		const byDefault = await github.fetch(GITHUB.tokenEndpoint, tokenRequest());
		expect(byDefault.headers.get("content-type")).toMatch(/^application\/x-www-form-urlencoded/);
		const form = new URLSearchParams(await byDefault.text());
		expect(form.get("access_token")).toBe(ACCESS_TOKEN);
		expect(form.get("token_type")).toBe("bearer");
		expect(form.get("scope")).toBe("read:user,user:email");

		const asJson = await github.fetch(GITHUB.tokenEndpoint, tokenRequest("application/json"));
		expect(asJson.headers.get("content-type")).toMatch(/^application\/json/);
		expect(await asJson.json()).toMatchObject({ access_token: ACCESS_TOKEN });
	});

	it("refuses a REST request without a User-Agent with 403", async () => {
		const github = createFakeGithub();
		const auth = { authorization: `Bearer ${ACCESS_TOKEN}` };

		const anonymous = await github.fetch(GITHUB.user, { headers: auth });
		expect(anonymous.status).toBe(403);
		expect(await anonymous.text()).toMatch(/User-Agent header/);

		const named = await github.fetch(GITHUB.user, {
			headers: { ...auth, "user-agent": "client-under-test" },
		});
		expect(named.status).toBe(200);
	});

	it("is satisfied by the adapter: the token request asks for JSON, and every request names a User-Agent", async () => {
		const github = createFakeGithub();
		const callback = "https://app.example.com/session/oauth/federation/github/callback";

		await createGithubProvider({
			clientId: "client-id",
			clientSecret: "client-secret",
			callbackURL: callback,
			fetch: github.fetch,
		}).exchangeCode({ code: "gh-code", codeVerifier: "v".repeat(43), redirectUri: callback });

		const [token] = github.requestsTo(GITHUB.tokenEndpoint);
		expect(token?.headers.get("accept")).toMatch(/application\/json/);
		expect(github.requests.map((r) => r.url.pathname)).toEqual([
			"/login/oauth/access_token",
			"/user",
			"/user/emails",
		]);
		for (const request of github.requests) {
			expect(request.headers.get("user-agent")).toBeTruthy();
		}
	});
});
