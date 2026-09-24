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

	it("reads an id that arrives as a string of digits as it is", async () => {
		github.user.body = { ...githubUser(), id: "12345" };

		expect((await exchange()).sub).toBe("12345");
	});

	it("reads the largest safe integer id exactly", async () => {
		github.user.raw = `{"login":"octocat","id":${Number.MAX_SAFE_INTEGER}}`;

		expect((await exchange()).sub).toBe("9007199254740991");
	});

	it("reads a string id above 2^53 exactly as sent — a string is never rounded", async () => {
		github.user.body = { ...githubUser(), id: "9007199254740993" };

		expect((await exchange()).sub).toBe("9007199254740993");
	});

	// GitHub types `id` as an int64 integer. The identity handed to the Store
	// is `github:<id>`, so an id JSON cannot carry exactly must not become one:
	// two users would read as the same account. Each body is sent as raw JSON
	// text so the adapter sees the number exactly as `JSON.parse` reads it.
	it.each([
		["zero", "0"],
		["negative", "-12345"],
		["a fraction", "12345.5"],
		["above 2^53 — 9007199254740993 parses as 9007199254740992", "9007199254740993"],
		["too large to be finite — 1e400 parses as Infinity", "1e400"],
	])("refuses a numeric id that is %s", async (_label, idText) => {
		github.user.raw = `{"login":"octocat","id":${idText}}`;

		await expect(exchange()).rejects.toThrow(/GitHub federation "github".*without id\/sub/);
	});

	it("does not read two users above 2^53 as one", async () => {
		// Unchecked, both of these became `github:9007199254740992`.
		const outcome = async (idText: string): Promise<string> => {
			github.user.raw = `{"login":"octocat","id":${idText}}`;
			try {
				return (await exchange()).sub;
			} catch {
				return "refused";
			}
		};

		const first = await outcome("9007199254740992");
		const second = await outcome("9007199254740993");

		expect([first, second]).toEqual(["refused", "refused"]);
	});

	it.each([
		["a leading zero", "012345"],
		["zero", "0"],
		["a minus sign", "-12345"],
		["a plus sign", "+12345"],
		["a fraction", "12345.5"],
		["an exponent", "1e5"],
		["surrounding whitespace", " 12345 "],
		["letters", "octocat"],
		["a hex prefix", "0x3039"],
		["non-ASCII digits", "١٢٣٤٥"],
	])("refuses a string id with %s", async (_label, id) => {
		github.user.body = { ...githubUser(), id };

		await expect(exchange()).rejects.toThrow(/GitHub federation "github".*without id\/sub/);
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

	it("releases the body of a /user that answers non-2xx instead of leaving it unread", async () => {
		github.user.status = 401;
		github.user.body = { message: "Bad credentials" };

		await expect(exchange()).rejects.toThrow(/HTTP 401/);
		const [user] = github.requestsTo(GITHUB.user);
		expect(user?.response.bodyUsed).toBe(true);
	});

	it("does not fetch /user/emails when /user is refused", async () => {
		github.user.status = 401;

		await expect(exchange()).rejects.toThrow();
		expect(github.requestsTo(GITHUB.emails)).toHaveLength(0);
	});
});
