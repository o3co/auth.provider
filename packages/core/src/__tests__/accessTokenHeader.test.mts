/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import { describe, expect, it } from "vitest";
import { parseAccessTokenAuthorization, parseAccessTokenHeader } from "#/accessTokenHeader.mjs";

describe("parseAccessTokenHeader (moved from oauth — #324)", () => {
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

	it("trims the optional whitespace RFC 9110 §5.6.3 permits around a field value", () => {
		expect(parseAccessTokenHeader("Bearer   abc.def  ")).toBe("abc.def");
	});
});

describe("parseAccessTokenAuthorization", () => {
	it("returns the lowercased scheme alongside the token", () => {
		// `protectedResourceBindingMw` needs the scheme to enforce RFC 9449
		// §7.1 (a jkt-bound token must arrive under `DPoP`); returning it
		// here is what lets the middleware drop its inline re-parse.
		expect(parseAccessTokenAuthorization("Bearer abc")).toEqual({
			scheme: "bearer",
			token: "abc",
		});
		expect(parseAccessTokenAuthorization("DPoP abc")).toEqual({ scheme: "dpop", token: "abc" });
		expect(parseAccessTokenAuthorization("DPOP abc")).toEqual({ scheme: "dpop", token: "abc" });
	});

	it("returns null exactly where parseAccessTokenHeader does", () => {
		expect(parseAccessTokenAuthorization(undefined)).toBeNull();
		expect(parseAccessTokenAuthorization("Bearer")).toBeNull();
		expect(parseAccessTokenAuthorization("Bearer ")).toBeNull();
		expect(parseAccessTokenAuthorization("Basic Y2xpZW50OnNlY3JldA==")).toBeNull();
		expect(parseAccessTokenAuthorization("BearerToken xyz")).toBeNull();
	});

	it("trims optional whitespace around the token", () => {
		expect(parseAccessTokenAuthorization("Bearer   abc.def  ")).toEqual({
			scheme: "bearer",
			token: "abc.def",
		});
	});
});
