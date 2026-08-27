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
import { parseAccessTokenHeader } from "#/accessTokenHeader.mjs";

describe("parseAccessTokenHeader", () => {
	it("accepts the Bearer scheme (RFC 6750 §2.1)", () => {
		expect(parseAccessTokenHeader("Bearer abc.def.ghi")).toBe("abc.def.ghi");
	});

	it("accepts the DPoP scheme (RFC 9449 §7.1)", () => {
		// A DPoP-bound token is presented under its own scheme; refusing it
		// here would make binding a token break every protected resource.
		expect(parseAccessTokenHeader("DPoP abc.def.ghi")).toBe("abc.def.ghi");
	});

	it("matches the scheme case-insensitively (RFC 9110 §11.1)", () => {
		expect(parseAccessTokenHeader("bearer abc")).toBe("abc");
		expect(parseAccessTokenHeader("dpop abc")).toBe("abc");
		expect(parseAccessTokenHeader("DPOP abc")).toBe("abc");
	});

	it("returns null for a scheme that carries no access token", () => {
		expect(parseAccessTokenHeader("Basic Y2xpZW50OnNlY3JldA==")).toBeNull();
		expect(parseAccessTokenHeader("Negotiate abc")).toBeNull();
	});

	it("returns null for a missing, empty, or scheme-only header", () => {
		expect(parseAccessTokenHeader(undefined)).toBeNull();
		expect(parseAccessTokenHeader("")).toBeNull();
		expect(parseAccessTokenHeader("Bearer")).toBeNull();
		expect(parseAccessTokenHeader("Bearer ")).toBeNull();
		expect(parseAccessTokenHeader("DPoP   ")).toBeNull();
	});

	it("does not treat a scheme-prefixed word as the scheme", () => {
		// `BearerToken xyz` is not the Bearer scheme; a prefix match would
		// accept it and hand `xyz` to the verifier as though it were.
		expect(parseAccessTokenHeader("BearerToken xyz")).toBeNull();
		expect(parseAccessTokenHeader("DPoPish xyz")).toBeNull();
	});

	it("trims the surrounding whitespace RFC 9110 §5.6.3 permits", () => {
		expect(parseAccessTokenHeader("Bearer   abc.def  ")).toBe("abc.def");
	});
});
