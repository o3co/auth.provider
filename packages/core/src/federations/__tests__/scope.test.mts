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
import { canonicalScope, isScopeToken, parseScopeTokens } from "../scope.mjs";

describe("isScopeToken — RFC 6749 §3.3's grammar", () => {
	it.each(["openid", "user:email", "read:user", "a", "~", "!"])("admits %s", (entry) => {
		expect(isScopeToken(entry)).toBe(true);
	});

	it.each([
		["the empty string", ""],
		["a space, which is the delimiter", " "],
		["a tab", "\t"],
		["a newline", "\n"],
		["a double quote, excluded by the grammar", '"'],
		["a backslash, excluded by the grammar", "\\"],
		["a name containing a quote", 'a"b'],
		["a name containing a backslash", "a\\b"],
		["a DEL", "\x7f"],
		["a control character", "\x01"],
		["a non-ASCII character", "é"],
	])("refuses %s", (_label, entry) => {
		expect(isScopeToken(entry)).toBe(false);
	});
});

describe("parseScopeTokens", () => {
	it.each([
		["one space", " "],
		["two spaces", "  "],
		["three spaces", "   "],
		["a tab alone", "\t"],
		["a newline alone", "\n"],
		["mixed whitespace", " \t\n "],
		["the empty string", ""],
	])("names nothing for %s", (_label, value) => {
		expect(parseScopeTokens(value)).toEqual([]);
	});

	it.each([
		["a single space", "openid email"],
		["several spaces", "openid   email"],
		["a tab", "openid\temail"],
		["a newline", "openid\nemail"],
	])("reads two scopes separated by %s as two", (_label, value) => {
		// Whitespace other than the space is not a delimiter in the grammar, but
		// no scope-token may contain it either, so splitting on all of it can
		// neither merge two tokens nor invent one.
		expect(parseScopeTokens(value)).toEqual(["openid", "email"]);
	});

	it("drops what the grammar excludes and keeps the rest", () => {
		expect(parseScopeTokens('openid "quoted" email')).toEqual(["openid", "email"]);
	});

	it("de-duplicates, keeping first appearance", () => {
		expect(parseScopeTokens("email openid email")).toEqual(["email", "openid"]);
	});

	it.each([
		["a number", 42],
		["null", null],
		["undefined", undefined],
		["an object", {}],
		["an array", ["openid"]],
	])("names nothing for %s, which is not a string (D5)", (_label, value) => {
		expect(parseScopeTokens(value)).toEqual([]);
	});
});

describe("canonicalScope", () => {
	it("answers the tokens, space-delimited", () => {
		expect(canonicalScope("  openid\temail  openid ")).toBe("openid email");
	});

	it("answers undefined when nothing is named", () => {
		expect(canonicalScope("   ")).toBeUndefined();
		expect(canonicalScope(undefined)).toBeUndefined();
	});
});
