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

import { UnsecuredJWT } from "jose";
import { describe, expect, it } from "vitest";
import { ownAccessTokenPins } from "#/ownAccessToken.mjs";

const tokenWith = (claims: Record<string, unknown>): string => new UnsecuredJWT(claims).encode();

describe("ownAccessTokenPins", () => {
	it("pins aud and azp to the client the token's azp names", () => {
		expect(ownAccessTokenPins(tokenWith({ azp: "client-1", aud: "rs" }))).toEqual({
			expectedAudience: "client-1",
			expectedAzp: "client-1",
		});
	});

	it.each([
		["no azp", {}],
		["an empty azp", { azp: "" }],
		["an azp that is not a string", { azp: ["client-1"] }],
	])("is null for a token with %s", (_label, claims) => {
		expect(ownAccessTokenPins(tokenWith(claims))).toBeNull();
	});

	it("is null for a value that is not a JWT", () => {
		expect(ownAccessTokenPins("not.a.jwt")).toBeNull();
		expect(ownAccessTokenPins("")).toBeNull();
	});
});
