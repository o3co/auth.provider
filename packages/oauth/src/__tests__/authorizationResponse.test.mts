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
 * The authorization-response builder on its own: what it appends, and that
 * it rewrites nothing a registered `redirect_uri` holds.
 */

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

	it("rewrites no registered query: a registered iss is kept beside the response's", () => {
		const url = new URL(authorizationResponseUrl("https://c/cb?iss=x", { code: "c" }, "s", ISS));
		expect(url.searchParams.getAll("iss")).toEqual(["x", ISS]);
	});
});

describe("authorizationResponseFor", () => {
	it("binds the issuer: the response it builds is authorizationResponseUrl's", () => {
		const respond = authorizationResponseFor(ISS);
		expect(respond("https://c/cb", { error: "access_denied" }, "s")).toBe(
			authorizationResponseUrl("https://c/cb", { error: "access_denied" }, "s", ISS),
		);
	});
});
