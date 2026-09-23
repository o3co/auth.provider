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
import {
	BEARER_TOKEN_TYPE,
	canonicalTokenType,
	isBearerTokenType,
} from "#/federations/token-type.mjs";

describe("canonicalTokenType — RFC 6749 §A.13's `token-type`", () => {
	it.each([
		["a type name", "Bearer"],
		["the spelling oauth4webapi reports", "bearer"],
		["another registered type", "DPoP"],
		// §A.13 is `token-type = type-name / URI-reference`, and this is only a
		// token type through the second alternative — `name-char` has no `:`.
		["a URI, which §A.13 admits beside a type name", "urn:ietf:params:oauth:token-type:jwt"],
		["an absolute URI with a query and a fragment", "https://example.com/tt?v=1#x"],
		["a pct-encoded octet", "a%20b"],
		["a relative reference", "foo/bar"],
		["a network-path reference", "//host/p"],
		["an IPv6 literal host", "https://[::1]/x"],
		["an IPvFuture literal host", "https://[v1.fe]/"],
		// RFC 5234 §2.3: an ABNF quoted literal is case-insensitive (#649 review).
		["an IPvFuture literal with an uppercase version marker", "https://[V1.fe]/"],
		["userinfo and a port", "https://u:p@h:8080/p"],
		["one the registry does not hold", "mac"],
	])("keeps %s exactly as it was given", (_label, value) => {
		expect(canonicalTokenType(value)).toBe(value);
	});

	it.each([
		["the empty string", ""],
		["a space", " "],
		["two names with a space between them", "Bearer token"],
		["a tab", "\t"],
		["a leading space", " Bearer"],
		["a trailing space", "Bearer "],
		["a double quote, which no URI may contain", '"'],
		["a backslash, which no URI may contain", "\\"],
		// Printable ASCII the old NQCHAR bound admitted and §A.13 does not:
		// neither a `name-char` nor a character RFC 3986 permits in a URI.
		// Reading these as names sent an adapter's garbage down the refusal
		// meant for a real type the upstream issued (#649 review).
		["a caret", "Bearer^"],
		["braces", "a{b}"],
		["a pipe", "a|b"],
		["a backtick", "a`b"],
		["angle brackets", "a<b>"],
		["a `%` that does not begin a pct-encoded octet", "a%zz"],
		["a truncated pct-encoding", "a%2"],
		["a non-ASCII letter", "é"],
		// Every character is one a URI may contain, and the reference is still
		// malformed. A lexical check read these as type names (#649 review).
		["an IP-literal that never closes", "https://["],
		["an IP-literal that is not an IP address", "https://[zz]/"],
		["a bracket outside an IP-literal", "a[b"],
		["a bracket in a path", "http://h/p[1]"],
		["a colon in a relative reference's first segment", ":foo"],
		["a port that is not a number", "http://h:80x"],
	])("names nothing for %s", (_label, value) => {
		expect(canonicalTokenType(value)).toBeUndefined();
	});

	it.each([
		["undefined", undefined],
		["null", null],
		["a number", 7],
		["an object", { toString: () => "Bearer" }],
		["an array", ["Bearer"]],
	])("names nothing for %s, which came from an adapter and is not believed", (_label, value) => {
		expect(canonicalTokenType(value)).toBeUndefined();
	});

	it("does not re-case what it keeps", () => {
		// The spelling is the upstream's. A comparison is case-insensitive
		// (§5.1); writing it down is not the place to decide that.
		expect(canonicalTokenType("bearer")).not.toBe(BEARER_TOKEN_TYPE);
	});
});

describe("isBearerTokenType — §5.1's case-insensitive comparison", () => {
	it.each(["Bearer", "bearer", "BEARER", "BeArEr"])("admits %s", (named) => {
		expect(isBearerTokenType(named)).toBe(true);
	});

	it.each([
		["DPoP, which is sender-constrained (RFC 9449)", "DPoP"],
		["PoP, which is sender-constrained (RFC 9200)", "PoP"],
		["N_A, which is not an access token type at all (RFC 8693 §2.2.1)", "N_A"],
		["a type the registry does not hold", "mac"],
		["a name that merely starts with it", "Bearer2"],
		["a name that merely contains it", "not-bearer"],
		["the empty string", ""],
		["a padded spelling, which is not a type name", " Bearer "],
	])("refuses %s", (_label, named) => {
		expect(isBearerTokenType(named)).toBe(false);
	});

	it.each([
		["undefined — a type nobody named is not judged here", undefined],
		["null", null],
		["a number", 7],
		["an object whose toString would say Bearer", { toString: () => "Bearer" }],
	])("refuses %s", (_label, named) => {
		expect(isBearerTokenType(named)).toBe(false);
	});

	it("is the spelling BEARER_TOKEN_TYPE is written in", () => {
		expect(isBearerTokenType(BEARER_TOKEN_TYPE)).toBe(true);
	});
});
