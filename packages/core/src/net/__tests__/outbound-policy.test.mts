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
import { matchesHostList, readHostEntry, urlHost } from "#/net/outbound-policy.mjs";

const list = (...entries: string[]) =>
	entries.map((entry) => {
		const pattern = readHostEntry(entry);
		if (pattern === undefined) throw new Error(`not an entry: ${entry}`);
		return pattern;
	});

describe("readHostEntry: a host-list entry, read as a URL's host is", () => {
	it("canonicalises a name: lower case, IDNA to punycode, one trailing dot removed", () => {
		expect(readHostEntry("RP.Example")).toEqual({ host: "rp.example", suffix: false });
		expect(readHostEntry("bücher.example")).toEqual({
			host: "xn--bcher-kva.example",
			suffix: false,
		});
		expect(readHostEntry("rp.example.")).toEqual({ host: "rp.example", suffix: false });
		expect(readHostEntry("  rp.example  ")).toEqual({ host: "rp.example", suffix: false });
	});

	it("reads a leading dot as a domain and every subdomain of it", () => {
		expect(readHostEntry(".corp.example")).toEqual({ host: "corp.example", suffix: true });
	});

	it("canonicalises an IP address in every spelling the URL parser accepts", () => {
		expect(readHostEntry("10.0.0.5")).toEqual({ host: "10.0.0.5", suffix: false });
		expect(readHostEntry("10.0.0.5.")).toEqual({ host: "10.0.0.5", suffix: false });
		expect(readHostEntry("0x7f000001")).toEqual({ host: "127.0.0.1", suffix: false });
		expect(readHostEntry("::1")).toEqual({ host: "[::1]", suffix: false });
		expect(readHostEntry("[0:0:0:0:0:0:0:1]")).toEqual({ host: "[::1]", suffix: false });
	});

	it("refuses anything that is not a bare host", () => {
		for (const entry of [
			"",
			"   ",
			".",
			"rp.example..",
			"https://rp.example",
			"rp.example/path",
			"rp.example:443",
			"user@rp.example",
			"rp.example?q",
			"rp.example#f",
			"rp example",
			"*.example.com",
			"*",
			"a,b.example",
			"rp_x.example",
			"-rp.example",
			"rp-.example",
			"rp.example!",
			`${"a".repeat(64)}.example`,
			".10.0.0.5",
			".[::1]",
			"[::1]:443",
			"[::1]:8080",
			"[::1]x",
		]) {
			expect(readHostEntry(entry), JSON.stringify(entry)).toBeUndefined();
		}
	});
});

describe("urlHost: a URL's host in the same canonical form", () => {
	it("drops one trailing dot and keeps the URL parser's canonical spellings", () => {
		expect(urlHost(new URL("https://RP.example./x"))).toBe("rp.example");
		expect(urlHost(new URL("https://2130706433/"))).toBe("127.0.0.1");
		expect(urlHost(new URL("https://[::ffff:10.0.0.5]/"))).toBe("[::ffff:a00:5]");
	});

	it("answers undefined for a host with an empty label", () => {
		expect(urlHost(new URL("https://rp.example../"))).toBeUndefined();
	});
});

describe("matchesHostList", () => {
	it("matches an exact entry, and a suffix entry for the domain and its subdomains", () => {
		const patterns = list("rp.example", ".corp.example");
		expect(matchesHostList(patterns, "rp.example")).toBe(true);
		expect(matchesHostList(patterns, "a.rp.example")).toBe(false);
		expect(matchesHostList(patterns, "corp.example")).toBe(true);
		expect(matchesHostList(patterns, "a.b.corp.example")).toBe(true);
		expect(matchesHostList(patterns, "evilcorp.example")).toBe(false);
	});

	it("matches across spellings: case, IDNA and a trailing dot on either side", () => {
		expect(matchesHostList(list("Bücher.Example."), "xn--bcher-kva.example")).toBe(true);
		expect(
			matchesHostList(list("rp.example"), urlHost(new URL("https://RP.EXAMPLE./")) ?? ""),
		).toBe(true);
	});

	it("matches an IPv4 entry against the IPv4-mapped and IPv4-translated literals of the same address", () => {
		const host = urlHost(new URL("https://[::ffff:10.0.0.5]/")) ?? "";
		expect(matchesHostList(list("10.0.0.5."), host)).toBe(true);
		expect(matchesHostList(list("10.0.0.6"), host)).toBe(false);
		const translated = urlHost(new URL("https://[::ffff:0:10.0.0.5]/")) ?? "";
		expect(matchesHostList(list("10.0.0.5"), translated)).toBe(true);
	});

	it("matches an IPv4-mapped entry against the IPv4 host of the same address, both sides read alike", () => {
		expect(
			matchesHostList(list("[::ffff:8.8.8.8]"), urlHost(new URL("https://8.8.8.8/")) ?? ""),
		).toBe(true);
		expect(matchesHostList(list("::ffff:0:8.8.8.8"), "8.8.8.8")).toBe(true);
		// The IPv4-compatible form reads the same.
		const compatible = urlHost(new URL("https://[::10.0.0.5]/")) ?? "";
		expect(matchesHostList(list("10.0.0.5"), compatible)).toBe(true);
		expect(matchesHostList(list("[::10.0.0.5]"), "10.0.0.5")).toBe(true);
		// The unspecified and loopback addresses embed nothing.
		expect(matchesHostList(list("0.0.0.1"), "[::1]")).toBe(false);
	});

	it("takes a URL's hostname as the parser gives it, a trailing dot included", () => {
		expect(matchesHostList(list("rp.example"), new URL("https://RP.example./").hostname)).toBe(
			true,
		);
	});

	it("reads its input as entries are read, whatever produced the hostname", () => {
		expect(matchesHostList(list("corp.example"), new URL("ldap://CORP.EXAMPLE/").hostname)).toBe(
			true,
		);
		expect(matchesHostList(list("corp.example"), "CORP.EXAMPLE.")).toBe(true);
		expect(
			matchesHostList(list(".corp.example"), new URL("https://a_b.corp.example/").hostname),
		).toBe(true);
		expect(matchesHostList(list("10.0.0.5"), "::ffff:10.0.0.5")).toBe(true);
		expect(() => matchesHostList([], "rp.example/path")).toThrow(TypeError);
	});

	it("refuses to answer for a hostname with an empty label, for an allow and a deny list alike", () => {
		const host = new URL("https://foo..corp.example/").hostname;
		expect(() => matchesHostList(list(".corp.example"), host)).toThrow(TypeError);
		expect(() => matchesHostList([], host)).toThrow(TypeError);
	});

	it("matches nothing when the list is empty", () => {
		expect(matchesHostList([], "rp.example")).toBe(false);
	});
});
