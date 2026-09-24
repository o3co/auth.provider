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
 * The user behind a GitHub login is read from `GET /user`, and the profile's
 * `sub` comes from it.
 *
 * `/user` is GitHub's REST API, not an OpenID Connect UserInfo endpoint: it
 * answers a numeric `id` and no `sub`. openid-client's `fetchUserInfo` refuses
 * such a body before it looks at `skipSubjectCheck`, so reading `/user` through
 * it failed every real login, while a unit test that mocked `fetchUserInfo`
 * passed. These cases run the real library against a fake GitHub, so what is
 * asserted is what a login does.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createGithubProvider } from "../github.mjs";
import {
	ACCESS_TOKEN,
	createFakeGithub,
	type FakeGithub,
	GITHUB,
	githubUser,
} from "./fake-github.mjs";

const CALLBACK = "https://app.example.com/session/oauth/federation/github/callback";
const CONFIG = { clientId: "client-id", clientSecret: "client-secret", callbackURL: CALLBACK };

let github: FakeGithub;

beforeEach(() => {
	github = createFakeGithub();
	vi.stubGlobal("fetch", github.fetch);
});

afterEach(() => {
	vi.unstubAllGlobals();
});

const exchange = () =>
	createGithubProvider(CONFIG).exchangeCode({
		code: "gh-code",
		codeVerifier: "verifier-0123456789-abcdef-0123456789-abcdef-0123456789abcdef",
		redirectUri: CALLBACK,
	});

describe("GitHub /user becomes the profile's sub", () => {
	it("signs in a user whose /user answers a numeric id and no sub, as GitHub's does", async () => {
		const profile = await exchange();

		expect(profile.sub).toBe("12345");
		expect(profile.issuer).toBe("https://github.com");
		const [userRequest] = github.requestsTo(GITHUB.user);
		expect(userRequest?.method).toBe("GET");
		expect(userRequest?.headers.get("authorization")).toBe(`Bearer ${ACCESS_TOKEN}`);
		expect(github.requestsTo(GITHUB.user)).toHaveLength(1);
	});

	it("reads the name and the avatar from the same /user answer", async () => {
		const profile = await exchange();

		expect(profile.name).toBe("The Octocat");
		expect(profile.picture).toBe("https://avatars.githubusercontent.com/u/12345?v=4");
	});

	it("takes a non-empty string sub over the id", async () => {
		github.user.body = { ...githubUser(), sub: "sub-from-upstream" };

		expect((await exchange()).sub).toBe("sub-from-upstream");
	});

	it("falls back to the id when sub is present but empty", async () => {
		github.user.body = { ...githubUser(), sub: "" };

		expect((await exchange()).sub).toBe("12345");
	});

	it("reads an id that arrives as a non-empty string as it is", async () => {
		github.user.body = { ...githubUser(), id: "12345" };

		expect((await exchange()).sub).toBe("12345");
	});

	it.each([
		["no id", undefined],
		["a null id", null],
		["an empty-string id", ""],
		["a boolean id", true],
		["an object id", { value: 12345 }],
	])("refuses a user object with %s and no sub", async (_label, id) => {
		const body: Record<string, unknown> = { ...githubUser(), id };
		if (id === undefined) delete body.id;
		github.user.body = body;

		await expect(exchange()).rejects.toThrow(/GitHub federation "github".*without id\/sub/);
	});

	it.each([
		["an array", []],
		["null", null],
		["a number", 12345],
	])("refuses a /user answer that is %s rather than an object", async (_label, body) => {
		github.user.body = body;

		await expect(exchange()).rejects.toThrow(/GitHub federation "github".*without id\/sub/);
	});

	it.each([
		[401, { message: "Bad credentials", documentation_url: "https://docs.github.com/rest" }],
		[403, { message: "Resource not accessible by integration" }],
		[500, { message: "Server Error" }],
	])("refuses a /user that answers HTTP %i, whatever its body", async (status, body) => {
		// A 401 body still carries no user; one that happened to carry an `id`
		// must not be read as one either.
		github.user.status = status;
		github.user.body = { ...body, id: 999 };

		await expect(exchange()).rejects.toThrow(
			new RegExp(`GitHub federation "github".*/user.*HTTP ${status}`),
		);
	});

	it("refuses a /user answer that is not JSON", async () => {
		github.user.raw = "<html><body>Unicorn!</body></html>";
		github.user.contentType = "text/html; charset=utf-8";

		await expect(exchange()).rejects.toThrow(/GitHub federation "github".*\/user.*not JSON/);
	});

	it("does not fetch /user/emails when /user is refused", async () => {
		github.user.status = 401;

		await expect(exchange()).rejects.toThrow();
		expect(github.requestsTo(GITHUB.emails)).toHaveLength(0);
	});
});
