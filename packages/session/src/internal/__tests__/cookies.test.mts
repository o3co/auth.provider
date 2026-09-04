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
 * The one cookie reader the CSRF double-submit check and the federation
 * transaction cookie share, so the two cannot disagree about what "the cookie
 * is present" means.
 */

import type { Request } from "express";
import { describe, expect, it } from "vitest";
import { readCookie } from "#/internal/cookies.mjs";

const fakeRequest = (init: { cookies?: unknown; header?: string }): Request =>
	({
		...(init.cookies === undefined ? {} : { cookies: init.cookies }),
		headers: init.header === undefined ? {} : { cookie: init.header },
	}) as unknown as Request;

describe("readCookie", () => {
	it("prefers cookie-parser's output when a composition root mounted it", () => {
		const req = fakeRequest({ cookies: { wanted: "from-parser" }, header: "wanted=from-header" });
		expect(readCookie(req, "wanted")).toBe("from-parser");
	});

	it("falls back to the raw header when cookie-parser is not mounted", () => {
		expect(readCookie(fakeRequest({ header: "a=1; wanted=value; b=2" }), "wanted")).toBe("value");
	});

	it("falls back to the header when cookie-parser holds nothing usable for this name", () => {
		// An empty string is not a value: a cookie-parser entry of "" must not
		// shadow a real value on the header.
		expect(
			readCookie(fakeRequest({ cookies: { wanted: "" }, header: "wanted=value" }), "wanted"),
		).toBe("value");
		expect(
			readCookie(fakeRequest({ cookies: { other: "x" }, header: "wanted=value" }), "wanted"),
		).toBe("value");
		expect(
			readCookie(fakeRequest({ cookies: { wanted: 42 }, header: "wanted=value" }), "wanted"),
		).toBe("value");
	});

	it("percent-decodes the header value", () => {
		expect(readCookie(fakeRequest({ header: "wanted=a%2Fb%2Bc" }), "wanted")).toBe("a/b+c");
	});

	it("hands back the raw text of a value that is not valid percent-encoding", () => {
		// Not a value we issued. Returning it raw lets the caller's own check
		// reject it, rather than throwing out of a request guard.
		expect(readCookie(fakeRequest({ header: "wanted=%E0%A4%A" }), "wanted")).toBe("%E0%A4%A");
	});

	it("returns undefined when the cookie is absent, however the request is shaped", () => {
		expect(readCookie(fakeRequest({ header: "other=1" }), "wanted")).toBeUndefined();
		expect(readCookie(fakeRequest({}), "wanted")).toBeUndefined();
		expect(readCookie(fakeRequest({ cookies: null }), "wanted")).toBeUndefined();
		expect(readCookie({} as Request, "wanted")).toBeUndefined();
	});

	it("ignores header fragments that are not name=value pairs, and matches the name exactly", () => {
		expect(readCookie(fakeRequest({ header: "novalue; wanted=v" }), "wanted")).toBe("v");
		// A prefix match would hand the CSRF check the transaction cookie.
		expect(readCookie(fakeRequest({ header: "wanted.suffix=v" }), "wanted")).toBeUndefined();
	});
});
