import { describe, expect, it } from "vitest";
import { hostEntryOf, listed, normalized, withinHosts } from "../src/contract.ts";
import { isListEntry } from "../src/entries.ts";

describe("host lists", () => {
	it("reads an entry as written, correcting nothing but case and Unicode, and refuses anything else", () => {
		expect(
			["a.example", ".A.Example", "Bücher.example", "10.0.0.1", "fd00::1", "[FD00::1]"].map(
				(entry) => hostEntryOf(entry),
			),
		).toEqual([
			{ kind: "name", name: "a.example", under: false },
			{ kind: "name", name: "a.example", under: true },
			{ kind: "name", name: "xn--bcher-kva.example", under: false },
			{ kind: "address", address: "10.0.0.1" },
			{ kind: "address", address: "fd00::1" },
			{ kind: "address", address: "fd00::1" },
		]);
		for (const entry of [
			"*.a.example",
			"*",
			".",
			"..a",
			".10.0.0.1",
			".10.0.5",
			"10.0.5",
			"010.0.0.1",
			"0x0a.0.0.1",
			"[10.0.0.1]",
			".[fd00::1]",
			"fe80::1%eth0",
			"[fe80::1%eth0]",
			"a..b",
			"a.example.",
			"a_b.example",
			" a.example",
			"a.example ",
			"a\texample",
			"-a.example",
			"a-.example",
			"a.123",
			"a.example:443",
			"https://a.example",
			"",
		]) {
			expect(hostEntryOf(entry), JSON.stringify(entry)).toBeUndefined();
			expect(isListEntry(entry), JSON.stringify(entry)).toBe(false);
		}
	});

	it("reads a host:port pair by the same reading, an IPv6 host in brackets and never .name", () => {
		expect(
			["A.Example:8080", "10.0.0.1:80", "[FD00::1]:65535"].map((pair) =>
				hostEntryOf(pair, { port: true }),
			),
		).toEqual([
			{ kind: "name", name: "a.example", under: false, port: 8080 },
			{ kind: "address", address: "10.0.0.1", port: 80 },
			{ kind: "address", address: "fd00::1", port: 65535 },
		]);
		for (const pair of [
			"a.example",
			"a.example:",
			"a.example:0",
			"a.example:08080",
			"a.example:65536",
			"fd00::1:80",
			".a.example:80",
			"a..b:80",
			"a_b:80",
			"10.5:80",
			"127.1:80",
			"a.example.:80",
			"[10.0.0.1]:80",
			"[::1%eth0]:443",
		]) {
			expect(hostEntryOf(pair, { port: true }), pair).toBeUndefined();
		}
		// Without a port, a pair is no host.
		expect(hostEntryOf("a.example:8080")).toBeUndefined();
	});

	it("matches a host exactly, or a name led by a dot and every name under it", () => {
		const entries = ["Exact.example", ".under.example", "10.0.0.5"];
		expect(
			["exact.example", "under.example", "a.under.example", "b.a.under.example", "10.0.0.5"].map(
				(host) => listed(host, entries),
			),
		).toEqual([true, true, true, true, true]);
		expect(
			["a.exact.example", "xunder.example", "example", "10.0.0.6"].map((host) =>
				listed(host, entries),
			),
		).toEqual([false, false, false, false]);
	});
});

describe("normalized", () => {
	it("spells a host one way", () => {
		expect(normalized("Example.COM.")).toBe("example.com");
		expect(normalized("::ffff:7f00:1")).toBe("127.0.0.1");
		expect(normalized("::1")).toBe("::1");
		expect(normalized("a..b")).toBeUndefined();
		expect(normalized("")).toBeUndefined();
		expect(normalized(".")).toBeUndefined();
		expect(normalized("::ffff:0:7f00:1")).toBe("127.0.0.1");
		expect(normalized("64:ff9b::7f00:1")).toBe("64:ff9b::7f00:1");
	});
});

describe("withinHosts", () => {
	it("tells whether a URL's host is among the hosts, as a caller spells them, compared normalized", () => {
		const hosts = ["idp.example", ".cdn.example", "[2001:DB8::1]"];
		for (const url of [
			"https://IDP.example/authorize",
			"https://idp.example./token",
			"https://keys.cdn.example/jwks",
			"https://cdn.example/jwks",
			"https://[2001:db8::1]/x",
		]) {
			expect(withinHosts(url, hosts), url).toBe(true);
		}
		for (const url of [
			"https://other.example/",
			"https://idp.example.evil/",
			"not a url",
			"https://xn--idp-.example/",
		]) {
			expect(withinHosts(url, hosts), url).toBe(false);
		}
		expect(withinHosts("https://idp.example/", [])).toBe(false);
		expect(withinHosts("https://keys.cdn.example/", ["*.cdn.example"])).toBe(false);
	});
});
