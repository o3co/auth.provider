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
 * The login page's URL rule (#728, #750): the one home of what `/authorize`'s
 * fallback and the session package's `loginEntry` both do to a login page —
 * refuse one whose own query already carries `redirect_to`, and add
 * `redirect_to` to its query, before any fragment, the target encoded whole.
 */

import { describe, expect, it } from "vitest";
import { LOGIN_RETURN_PARAMETER, loginPageCarriesReturn, loginPageUrlFor } from "#/index.mjs";

describe("loginPageCarriesReturn", () => {
	it.each([
		["a path", "/login?redirect_to=https://x"],
		["an absolute URL", "https://login.example/signin?tenant=x&redirect_to=https%3A%2F%2Fx"],
		["the name percent-encoded", "/login?redirect%5Fto=x"],
		["the name with no value", "/login?tenant=x&redirect_to"],
		["a URL that URL cannot parse", "http://[::1/login?redirect_to=x"],
		["a query with a fragment after it", "/login?redirect_to=y#z"],
	])("is true for %s whose own query carries redirect_to", (_label, page) => {
		expect(loginPageCarriesReturn(page)).toBe(true);
	});

	it.each([
		["no query", "/login"],
		["a query of its own", "/login?tenant=x"],
		["redirect_to inside the fragment alone", "/login#redirect_to=https://x"],
		["a `?` inside the fragment alone", "/login#a?redirect_to=x"],
		["a name that differs in case", "/login?Redirect_To=x"],
		["a longer name", "/login?redirect_to_after=x"],
	])("is false for a page with %s", (_label, page) => {
		expect(loginPageCarriesReturn(page)).toBe(false);
	});
});

describe("loginPageUrlFor", () => {
	it("names the parameter redirect_to", () => {
		expect(LOGIN_RETURN_PARAMETER).toBe("redirect_to");
	});

	it.each([
		["/login", "/login?redirect_to=%2Fback%3Fa%3D1%23f"],
		["/login?tenant=x", "/login?tenant=x&redirect_to=%2Fback%3Fa%3D1%23f"],
		["/login#x", "/login?redirect_to=%2Fback%3Fa%3D1%23f#x"],
		["/login?tenant=x#y", "/login?tenant=x&redirect_to=%2Fback%3Fa%3D1%23f#y"],
		["/login#a?b", "/login?redirect_to=%2Fback%3Fa%3D1%23f#a?b"],
		[
			"https://login.example/signin?tenant=x#y",
			"https://login.example/signin?tenant=x&redirect_to=%2Fback%3Fa%3D1%23f#y",
		],
	])(
		"adds redirect_to to %s's query, before its fragment, the target encoded whole",
		(page, sent) => {
			expect(loginPageUrlFor(page, "/back?a=1#f")).toBe(sent);
		},
	);

	it("encodes a space as %20, never as a form's +", () => {
		expect(loginPageUrlFor("/login", "/a b")).toBe("/login?redirect_to=%2Fa%20b");
	});
});
