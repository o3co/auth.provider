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
 * The authorization-response builder on its own: what it appends, that it
 * rewrites nothing in the query it is handed, and that every name it appends
 * is one core's `checkRedirectUri` refuses in a registered query.
 */

import { checkRedirectUri } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import {
	authorizationResponseFor,
	authorizationResponseUrl,
} from "#/routes/authorizationResponse.mjs";

const ISS = "https://issuer.example";

describe("authorizationResponseUrl", () => {
	it("appends the parameters, then state, then iss", () => {
		const url = new URL(authorizationResponseUrl("https://c/cb", { code: "c" }, "s", ISS));
		expect([...url.searchParams]).toEqual([
			["code", "c"],
			["state", "s"],
			["iss", ISS],
		]);
	});

	it("sends no state when the request carried none", () => {
		const url = new URL(authorizationResponseUrl("https://c/cb", { code: "c" }, undefined, ISS));
		expect(url.searchParams.has("state")).toBe(false);
		expect(url.searchParams.getAll("iss")).toEqual([ISS]);
	});

	// Refusing such a URI is `checkRedirectUri`'s job, at registration and on
	// each path that answers; the builder appends and checks nothing.
	it("rewrites nothing in the query it is handed, a name it appends included", () => {
		const url = new URL(authorizationResponseUrl("https://c/cb?iss=x", { code: "c" }, "s", ISS));
		expect(url.searchParams.getAll("iss")).toEqual(["x", ISS]);
	});
});

describe("the names the builder appends", () => {
	/** The names a code response and an error response carry, both with state. */
	const appended = [
		...new URL(
			authorizationResponseUrl("https://c/cb", { code: "c" }, "s", ISS),
		).searchParams.keys(),
		...new URL(
			authorizationResponseUrl(
				"https://c/cb",
				{ error: "access_denied", error_description: "d" },
				"s",
				ISS,
			),
		).searchParams.keys(),
	];

	it("are the response parameters: code, state, iss, error, error_description", () => {
		expect(new Set(appended)).toEqual(
			new Set(["code", "state", "iss", "error", "error_description"]),
		);
	});

	it.each([...new Set(appended)])(
		"%s is a name checkRedirectUri refuses in a registered query",
		(name) => {
			expect(checkRedirectUri(`https://c/cb?${name}=x`)).toEqual({
				reason: "reserved-parameter",
				parameter: name,
			});
		},
	);
});

describe("authorizationResponseFor", () => {
	it("binds the issuer: the response it builds is authorizationResponseUrl's", () => {
		const respond = authorizationResponseFor(ISS);
		expect(respond("https://c/cb", { error: "access_denied" }, "s")).toBe(
			authorizationResponseUrl("https://c/cb", { error: "access_denied" }, "s", ISS),
		);
	});
});
