import { configuredUrl } from "@mod/url-setting/testing";
import { describe, expect, it } from "vitest";
import { DestinationRefused, type RefusalReason } from "../src/contract.ts";
import {
	admitAddresses,
	admitUrl,
	hostEntryOf,
	isListEntry,
	listed,
	normalized,
	type Rules,
} from "../src/policy.ts";

const open: Rules = { allow: [], anyPublic: true, deny: [], plainLoopback: [], internal: [] };
const reasonOf = (run: () => unknown): RefusalReason | "admitted" => {
	try {
		run();
		return "admitted";
	} catch (error) {
		if (error instanceof DestinationRefused) return error.reason;
		throw error;
	}
};
/** How a URL is admitted under `open` changed as given, narrowed to `hosts` where named. */
const url = (raw: string, policy: Partial<Rules> = {}, hosts?: readonly string[], signed = false) =>
	reasonOf(() => admitUrl(raw, { ...open, ...policy }, hosts ? { hosts } : {}, signed));

describe("admitUrl", () => {
	it("admits https to any host when any public address is allowed, at its port", () => {
		const admitted = admitUrl("https://Example.COM.:8443/p?q=1", open);
		expect([admitted.host, admitted.port, admitted.plain]).toEqual(["example.com", 8443, false]);
		expect(admitUrl("https://example.com/", open).port).toBe(443);
	});

	it("refuses other schemes, userinfo and bad ports", () => {
		expect(url("ftp://example.com/")).toBe("scheme");
		expect(url("not a url")).toBe("scheme");
		expect(url("http://example.com/")).toBe("scheme");
		expect(url("https://user@example.com/")).toBe("userinfo");
		expect(url("https://:secret@example.com/")).toBe("userinfo");
		expect(url("https://example.com:0/")).toBe("port");
		expect(url("https://example.com:22/")).toBe("port");
		// The Fetch standard's bad ports, copied apart from the source's list.
		const fetchBad =
			"1 7 9 11 13 15 17 19 20 21 22 23 25 37 42 43 53 69 77 79 87 95 101 102 103 104 109 110 111 113 115 117 119 123 135 137 139 143 161 179 389 427 465 512 513 514 515 526 530 531 532 540 548 554 556 563 587 601 636 989 990 993 995 1719 1720 1723 2049 3659 4045 4190 5060 5061 6000 6566 6665 6666 6667 6668 6669 6679 6697 10080";
		for (const port of fetchBad.split(" ")) {
			expect(url(`https://example.com:${port}/`), port).toBe("port");
		}
		expect(url("https://example.com:10081/")).toBe("admitted");
	});

	it("lets deny win over allow, matching every spelling of a host alike", () => {
		expect(url("https://a.example/", { allow: ["a.example"], deny: ["A.Example."] })).toBe(
			"denied",
		);
		expect(url("https://EVIL.example./", { deny: ["evil.example"] })).toBe("denied");
		expect(url("https://xn--bcher-kva.example/", { deny: ["bücher.example"] })).toBe("denied");
		expect(url("https://bücher.example/", { deny: ["xn--bcher-kva.example"] })).toBe("denied");
		for (const spelled of [
			"127.0.0.1",
			"[::ffff:127.0.0.1]",
			"[::ffff:7f00:1]",
			"2130706433",
			"0x7f.1",
			"017700000001",
			"[::127.0.0.1]",
			"[::ffff:0:7f00:1]",
		]) {
			expect(url(`https://${spelled}/`, { deny: ["127.0.0.1"] }), spelled).toBe("denied");
		}
		expect(url("https://a..example/")).toBe("denied");
	});

	it("allows only what is allowed by name, IPv6 entries included, and nothing by a wildcard", () => {
		const named = (...allow: string[]) => ({ allow, anyPublic: false });
		expect(url("https://b.example/", named("a.example"))).toBe("not-allowed");
		expect(url("https://[2001:0db8:0::1]/", named("2001:db8::1"))).toBe("admitted");
		expect(url("https://[2001:db8::1]/", named("[2001:DB8::1]"))).toBe("admitted");
		expect(url("https://x.y.example/", named("*.example"))).toBe("not-allowed");
		expect(url("https://example/", named("*.example"))).toBe("not-allowed");
	});

	it("reads a leading dot in allow, deny and a caller's hosts as the name and every name under it", () => {
		const named = (...allow: string[]) => ({ allow, anyPublic: false });
		expect(url("https://x.y.example/", named(".example"))).toBe("admitted");
		expect(url("https://example/", named(".Example"))).toBe("admitted");
		expect(url("https://other/", named(".example"))).toBe("not-allowed");
		expect(url("https://evil.example/", { deny: [".evil.example"] })).toBe("denied");
		expect(url("https://a.evil.example/", { deny: [".evil.example"] })).toBe("denied");
		expect(url("https://a.example/", {}, [".a.example"])).toBe("admitted");
		expect(url("https://b.a.example/", {}, [".a.example"])).toBe("admitted");
		expect(url("https://b.example/", {}, [".a.example"])).toBe("not-allowed");
	});

	it("reaches no host while none is allowed by name and any public address is not", () => {
		const closed = { anyPublic: false };
		expect(url("https://a.example/", closed)).toBe("not-allowed");
		expect(url("https://a.example/", closed, ["a.example"])).toBe("not-allowed");
		expect(url("https://a.example/", { ...closed, deny: ["a.example"] })).toBe("denied");
	});

	it("lets a caller narrow the hosts, never widen them", () => {
		expect(url("https://a.example/", {}, ["b.example"])).toBe("not-allowed");
		expect(url("https://A.example./", {}, ["a.example"])).toBe("admitted");
		expect(
			url("https://b.example/", { allow: ["a.example"], anyPublic: false }, ["b.example"]),
		).toBe("not-allowed");
	});

	it("reaches plain http only at a named loopback host and port", () => {
		const policy = { plainLoopback: ["LOCALHOST.:8080"] };
		const admitted = admitUrl("http://localhost:8080/", { ...open, ...policy });
		expect([admitted.plain, admitted.loopback]).toEqual([true, true]);
		expect(admitUrl("https://localhost:8080/", { ...open, ...policy }).loopback).toBe(false);
		expect(url("http://localhost:8081/", policy)).toBe("scheme");
		expect(url("http://other:8080/", policy)).toBe("scheme");
		const v6 = admitUrl("http://[::1]:8080/", { ...open, plainLoopback: ["[::1]:8080"] });
		expect(v6.loopback).toBe(true);
	});

	it("takes a host as internal only when the caller's URL is the operator's and internal-hosts lists it", () => {
		const policy = { ...open, internal: ["ALB.corp", ".svc.corp", "10.0.0.5"] };
		const internal = (raw: string) =>
			admitUrl(raw, policy, { internal: configuredUrl(raw) }).internal;
		expect(internal("https://alb.corp/")).toBe(true);
		expect(internal("https://a.b.svc.corp/")).toBe(true);
		expect(internal("https://10.0.0.5/")).toBe(true);
		expect(internal("https://svc.corp/"), "a leading dot covers the name itself too").toBe(true);
		expect(internal("https://other.corp/")).toBe(false);
		expect(admitUrl("https://alb.corp/", policy).internal, "a URL from elsewhere").toBe(false);
	});

	it("takes a host as internal for the operator's configured URL only at that URL's origin", () => {
		const policy = { ...open, internal: ["alb.corp"], plainLoopback: [] };
		const configured = configuredUrl("https://alb.corp/verify");
		const internal = (raw: string) => admitUrl(raw, policy, { internal: configured }).internal;
		expect(internal("https://alb.corp/subject")).toBe(true);
		// Another port is another service on that host; another scheme another origin.
		expect(internal("https://alb.corp:8443/verify")).toBe(false);
		expect(
			reasonOf(() => admitUrl("http://alb.corp/verify", policy, { internal: configured })),
		).toBe("scheme");
		expect(internal("https://other.corp/verify")).toBe(false);
	});

	it("compares origins as the URL parser writes them, and holds each to its own configured URL", () => {
		// Two internal hosts: each reached only for its own URL, though both are listed.
		const policy = {
			...open,
			internal: ["alb.corp", "db.corp", "xn--bcher-kva.corp", "[fd00::1]"],
		};
		const reach = (raw: string, own: string) =>
			admitUrl(raw, policy, { internal: configuredUrl(own) }).internal;
		expect(reach("https://ALB.corp:443/x", "https://alb.corp/")).toBe(true);
		expect(reach("https://bücher.corp/x", "https://xn--bcher-kva.corp/")).toBe(true);
		expect(reach("https://[fd00:0::1]/x", "https://[fd00::1]/")).toBe(true);
		expect(reach("https://db.corp/x", "https://alb.corp/")).toBe(false);
		expect(reach("https://alb.corp/x", "https://db.corp/")).toBe(false);
		// Plain http admitted at a named pair, then held to the configured https origin: not its own.
		const plain = { ...policy, plainLoopback: ["alb.corp:443"] };
		const admitted = admitUrl("http://alb.corp:443/x", plain, {
			internal: configuredUrl("https://alb.corp/"),
		});
		expect([admitted.loopback, admitted.internal]).toEqual([true, false]);
	});
});

describe("admitUrl for signed material", () => {
	const signed = (raw: string, policy: Partial<Rules>, hosts: readonly string[] | undefined) =>
		url(raw, policy, hosts, true);

	it("reaches plain http at the caller's hosts alone, at public addresses", () => {
		const admitted = admitUrl("http://crl.example/a.crl", open, { hosts: ["crl.example"] }, true);
		expect([admitted.plain, admitted.loopback]).toEqual([true, false]);
		expect(signed("https://crl.example/", {}, ["crl.example"])).toBe("admitted");
		expect(signed("http://crl.example/", {}, undefined)).toBe("not-allowed");
		expect(signed("http://crl.example/", {}, [])).toBe("not-allowed");
		expect(signed("http://other.example/", {}, ["crl.example"])).toBe("not-allowed");
		expect(signed("ftp://crl.example/", {}, ["crl.example"])).toBe("scheme");
		expect(signed("http://crl.example/", { deny: ["crl.example"] }, ["crl.example"])).toBe(
			"denied",
		);
		expect(signed("http://crl.example/", { anyPublic: false }, ["crl.example"])).toBe(
			"not-allowed",
		);
		const pair = { plainLoopback: ["localhost:8080"] };
		expect(
			admitUrl("http://localhost:8080/", { ...open, ...pair }, { hosts: ["localhost"] }, true)
				.loopback,
		).toBe(true);
	});
});

describe("admitAddresses", () => {
	const addresses = (list: readonly string[], plain = false, internal = false) =>
		reasonOf(() => admitAddresses(list, { loopback: plain, internal }));

	/** Each special-purpose block: addresses inside, its first and last among them, and its public neighbours. */
	const blocks: Record<string, { inside: readonly string[]; outside: readonly string[] }> = {
		"0.0.0.0/8": { inside: ["0.0.0.0", "0.255.255.255"], outside: ["1.0.0.0"] },
		"10.0.0.0/8": { inside: ["10.1.2.3", "10.255.255.255"], outside: ["11.0.0.0"] },
		"100.64.0.0/10": { inside: ["100.64.0.1", "100.127.255.255"], outside: ["100.0.0.0"] },
		"127.0.0.0/8": { inside: ["127.0.0.1", "127.255.255.255"], outside: ["126.0.0.0"] },
		"169.254.0.0/16": { inside: ["169.254.1.1", "169.254.255.255"], outside: ["169.255.0.0"] },
		"172.16.0.0/12": { inside: ["172.16.0.1", "172.31.255.255"], outside: ["172.0.0.0"] },
		"192.0.0.0/24": { inside: ["192.0.0.1", "192.0.0.255"], outside: ["192.0.1.0"] },
		"192.0.2.0/24": { inside: ["192.0.2.1", "192.0.2.255"], outside: ["192.0.3.0"] },
		"192.88.99.0/24": { inside: ["192.88.99.1", "192.88.99.255"], outside: ["192.88.98.0"] },
		"192.168.0.0/16": { inside: ["192.168.1.1", "192.168.255.255"], outside: ["192.169.0.0"] },
		"198.18.0.0/15": { inside: ["198.18.0.1", "198.19.255.255"], outside: ["198.16.0.0"] },
		"198.51.100.0/24": { inside: ["198.51.100.1", "198.51.100.255"], outside: ["198.51.101.0"] },
		"203.0.113.0/24": { inside: ["203.0.113.1", "203.0.113.255"], outside: ["203.0.112.0"] },
		"224.0.0.0/4": { inside: ["224.0.0.1", "239.255.255.255"], outside: [] },
		"240.0.0.0/4": { inside: ["240.0.0.1", "255.255.255.255"], outside: [] },
		"IPv4 carried in IPv6": {
			inside: [
				"::ffff:8.8.8.8",
				"::ffff:a00:1",
				"::ffff:0:a00:1",
				"::a00:1",
				"::ffff:ffff:ffff",
				"::ffff:ffff",
				"::ffff:0:ffff:ffff",
			],
			outside: [],
		},
		"below global unicast": {
			inside: [
				"::",
				"::1",
				"64:ff9b::808:808",
				"64:ff9b::ffff:ffff",
				"64:ff9b:1::1",
				"64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
				"100::1",
				"100::ffff:ffff:ffff:ffff",
				"100:0:0:1::1",
				"100::1:ffff:ffff:ffff:ffff",
				"1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
			],
			outside: ["2000::"],
		},
		"2001::/23": {
			inside: ["2001::1", "2001:2::1", "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff"],
			outside: ["2001:200::"],
		},
		"2001:db8::/32": {
			inside: ["2001:db8::1", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"],
			outside: ["2001:db9::"],
		},
		"2002::/16": {
			inside: ["2002::1", "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
			outside: ["2003::"],
		},
		"3fff::/20": {
			inside: ["3fff::1", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff"],
			outside: ["3fff:1000::", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
		},
		"above global unicast": {
			inside: [
				"4000::",
				"5f00::1",
				"5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				"fc00::1",
				"fd00::1",
				"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				"fe80::1",
				"fec0::1",
				"febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				"feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				"ff02::1",
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
			],
			outside: [],
		},
	};

	it("refuses each special-purpose block whole, and admits its public neighbours", () => {
		expect(addresses(["93.184.216.34", "2606:4700::1111"])).toBe("admitted");
		for (const [block, { inside, outside }] of Object.entries(blocks)) {
			for (const address of inside) {
				expect(addresses([address]), `${block}: ${address}`).toBe("special-address");
			}
			for (const address of outside) {
				expect(addresses([address]), `${block}: ${address}`).toBe("admitted");
			}
		}
	});

	it("refuses them all for one special-purpose address among many, and refuses none", () => {
		expect(addresses(["8.8.8.8", "10.0.0.1"])).toBe("special-address");
		expect(addresses([])).toBe("special-address");
	});

	it("reaches plain http only at loopback addresses", () => {
		expect(addresses(["127.0.0.1", "::1", "::ffff:127.0.0.2"], true)).toBe("admitted");
		expect(addresses(["127.0.0.1", "8.8.8.8"], true)).toBe("special-address");
		// NAT64 is not IPv4 carried in IPv6, so not loopback either.
		expect(addresses(["64:ff9b::7f00:1"], true)).toBe("special-address");
	});

	it("reaches a private address for an internal host alone, and no other special-purpose one", () => {
		const privately = [
			["10.0.0.0", "10.255.255.255", "::ffff:10.0.0.1"],
			["172.16.0.0", "172.31.255.255"],
			["192.168.0.0", "192.168.255.255"],
			["100.64.0.0", "100.127.255.255"],
			["fc00::", "fd00::1", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
		].flat();
		for (const address of privately) {
			expect(addresses([address], false, true), address).toBe("admitted");
			expect(addresses([address]), address).toBe("special-address");
		}
		expect(addresses(["10.0.0.1", "8.8.8.8"], false, true)).toBe("admitted");
		// Loopback, link-local, the cloud metadata addresses (some inside the private ranges) and the rest stay refused.
		for (const address of [
			"127.0.0.1",
			"::1",
			"169.254.169.254",
			"fd00:ec2::254",
			"100.100.100.200",
			"::ffff:100.100.100.200",
			"fd20:ce::254",
			"fe80::1",
			"0.0.0.0",
			"224.0.0.1",
			"255.255.255.255",
			"192.0.2.1",
			"fe00::1",
		]) {
			expect(addresses([address], false, true), address).toBe("special-address");
		}
		expect(
			addresses(["172.32.0.0", "192.169.0.0", "100.128.0.0", "100.100.100.201"], false, true),
		).toBe("admitted");
		expect(addresses(["10.0.0.1", "127.0.0.1"], false, true)).toBe("special-address");
	});
});

describe("host lists", () => {
	it("reads an entry as written, correcting nothing but case and Unicode, and refuses anything else", () => {
		expect(
			["a.example", ".A.Example", "Bücher.example", "10.0.0.1", "fd00::1", "[FD00::1]"].map(
				hostEntryOf,
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
