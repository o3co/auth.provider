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
import { callbackUrlForExchange } from "#/federations/callback-url.mjs";

const CALLBACK = "https://auth.test/session/oauth/federation/idp-a/callback";

describe("callbackUrlForExchange (#597)", () => {
	it("puts the code on the registered callback", () => {
		const url = callbackUrlForExchange({ redirectUri: CALLBACK, code: "code-1" });
		expect(`${url.origin}${url.pathname}`).toBe(CALLBACK);
		expect([...url.searchParams.keys()]).toEqual(["code"]);
		expect(url.searchParams.get("code")).toBe("code-1");
	});

	it("forwards the RFC 9207 iss parameter when the callback carried one", () => {
		const url = callbackUrlForExchange({
			redirectUri: CALLBACK,
			code: "code-1",
			callbackParams: { iss: "https://idp-a.test" },
		});
		expect(url.searchParams.get("iss")).toBe("https://idp-a.test");
	});

	it("forwards nothing else from the bag", () => {
		const url = callbackUrlForExchange({
			redirectUri: CALLBACK,
			code: "code-1",
			callbackParams: {
				iss: "https://idp-a.test",
				error: "access_denied",
				response: "jarm.response.jwt",
				id_token: "hybrid.id.token",
				token: "implicit-access-token",
				state: "state-from-the-bag",
				user: '{"name":{"firstName":"A"}}',
			},
		});
		expect([...url.searchParams.keys()].sort()).toEqual(["code", "iss"]);
	});

	it("keeps an empty iss as it came, for the library to judge", () => {
		const url = callbackUrlForExchange({
			redirectUri: CALLBACK,
			code: "code-1",
			callbackParams: { iss: "" },
		});
		expect(url.searchParams.has("iss")).toBe(true);
		expect(url.searchParams.get("iss")).toBe("");
	});

	it("encodes the value, so an iss cannot smuggle another parameter", () => {
		const url = callbackUrlForExchange({
			redirectUri: CALLBACK,
			code: "code-1",
			callbackParams: { iss: "https://idp-a.test&error=access_denied" },
		});
		expect([...url.searchParams.keys()].sort()).toEqual(["code", "iss"]);
		expect(url.searchParams.get("iss")).toBe("https://idp-a.test&error=access_denied");
	});

	it("replaces a code or iss already on the redirect URI", () => {
		const url = callbackUrlForExchange({
			redirectUri: `${CALLBACK}?code=stale&iss=https%3A%2F%2Fstale.test`,
			code: "code-1",
			callbackParams: { iss: "https://idp-a.test" },
		});
		expect(url.searchParams.getAll("code")).toEqual(["code-1"]);
		expect(url.searchParams.getAll("iss")).toEqual(["https://idp-a.test"]);
	});

	it("drops a stale iss on the redirect URI when the callback carried none", () => {
		const url = callbackUrlForExchange({
			redirectUri: `${CALLBACK}?iss=https%3A%2F%2Fstale.test`,
			code: "code-1",
		});
		expect(url.searchParams.has("iss")).toBe(false);
	});
});
