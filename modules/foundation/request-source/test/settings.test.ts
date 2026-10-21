import { expect, it } from "vitest";
import { addressesOf, addressList, proxiesOf, sourceSettings } from "../src/contract.ts";

const takes = (entry: string) => sourceSettings.safeParse({ "trusted-proxies": [entry] }).success;

it("takes trusted proxies as IP addresses or CIDR blocks", () => {
	for (const entry of ["10.0.0.1", "10.0.0.0/8", "0.0.0.0/1", "2001:db8::/32", "::1/128"]) {
		expect(takes(entry), entry).toBe(true);
	}
	const { trusted } = proxiesOf(
		sourceSettings.parse({ "trusted-proxies": ["10.0.0.0/8", "2001:db8::1"] }),
	);
	expect([trusted.check("10.9.9.9", "ipv4"), trusted.check("11.0.0.1", "ipv4")]).toEqual([
		true,
		false,
	]);
	expect(trusted.check("2001:db8::1", "ipv6")).toBe(true);
});

it("refuses trusted proxies that together cover every address of a family, at the list", () => {
	const together = [
		["0.0.0.0/1", "128.0.0.0/1"],
		["::ffff:0:0/97", "::ffff:128.0.0.0/97"],
		["0.0.0.0/1", "::ffff:128.0.0.0/97"],
		[
			"10.0.0.0/8",
			"0.0.0.0/5",
			"8.0.0.0/7",
			"11.0.0.0/8",
			"12.0.0.0/6",
			"16.0.0.0/4",
			"32.0.0.0/3",
			"64.0.0.0/2",
			"128.0.0.0/1",
		],
	];
	for (const entries of together) {
		const issues = sourceSettings.safeParse({ "trusted-proxies": entries }).error?.issues ?? [];
		expect(
			issues.map((issue) => issue.path.join(".")),
			entries.join(),
		).toEqual(["trusted-proxies"]);
		expect(issues[0]?.message, entries.join()).toContain("together cover every address");
	}
	// One address short of a family, or a family's halves across the two families, is a proxy's own range.
	for (const entries of [
		[
			"0.0.0.0/1",
			"128.0.0.0/2",
			"192.0.0.0/3",
			"224.0.0.0/4",
			"240.0.0.0/5",
			"248.0.0.0/6",
			"252.0.0.0/7",
			"254.0.0.0/8",
			"255.0.0.0/9",
			"255.128.0.0/10",
			"255.192.0.0/11",
			"255.224.0.0/12",
			"255.240.0.0/13",
			"255.248.0.0/14",
			"255.252.0.0/15",
			"255.254.0.0/16",
			"255.255.0.0/17",
			"255.255.128.0/18",
			"255.255.192.0/19",
			"255.255.224.0/20",
			"255.255.240.0/21",
			"255.255.248.0/22",
			"255.255.252.0/23",
			"255.255.254.0/24",
			"255.255.255.0/25",
			"255.255.255.128/26",
			"255.255.255.192/27",
			"255.255.255.224/28",
			"255.255.255.240/29",
			"255.255.255.248/30",
			"255.255.255.252/31",
			"255.255.255.254",
		],
		["0.0.0.0/1", "8000::/1"],
		["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"],
	]) {
		expect(sourceSettings.safeParse({ "trusted-proxies": entries }).success, entries.at(-1)).toBe(
			true,
		);
	}
});

it("refuses a trusted proxy covering every address of a family, however written, as no source could be told", () => {
	const everyAddress = ["0.0.0.0/0", "10.1.2.3/0", "::/0", "2001:db8::/0", "::ffff:0:0/0"];
	// Every IPv4 address, mapped into IPv6, as an IPv4-mapped peer is checked as IPv4.
	const everyIpv4 = ["::ffff:0:0/96", "::ffff:0:0/95", "::/1", "::/64"];
	for (const entry of [...everyAddress, ...everyIpv4]) {
		const issues = sourceSettings.safeParse({ "trusted-proxies": [entry] }).error?.issues ?? [];
		expect(
			issues.map((issue) => issue.path.join(".")),
			entry,
		).toEqual(["trusted-proxies.0"]);
		expect(issues[0]?.message, entry).toContain("every source would be undetermined");
	}
	// A block of part of a family is a proxy's own range.
	for (const entry of ["10.0.0.0/8", "::ffff:0:0/97", "8000::/1", "2001:db8::/32"]) {
		expect(sourceSettings.safeParse({ "trusted-proxies": [entry] }).success, entry).toBe(true);
	}
	// An address list elsewhere may still hold every address.
	expect(addressList().safeParse(["0.0.0.0/0", "::/0"]).success).toBe(true);
});

it("refuses an entry not of that shape", () => {
	for (const entry of [
		"10.0.0.0/8/32",
		"10.0.0.0/",
		"10.0.0.0/08",
		"10.0.0.0/+8",
		"10.0.0.0/33",
		"::/129",
		"/8",
		"fe80::1%eth0",
		"fe80::%eth0/64",
		"010.0.0.1",
		" 10.0.0.1",
		"a.example",
	]) {
		expect(takes(entry), entry).toBe(false);
	}
});

it("refuses to make a trusted list of an entry the schema refuses", () => {
	expect(() => proxiesOf({ "trusted-proxies": ["10.0.0.0/8/32"], "proxy-hops": 1 })).toThrow(
		/not a trusted proxy entry/,
	);
});

it("takes hops from 1 to 10, and none trusted by default", () => {
	const parses = (hops: number) => sourceSettings.safeParse({ "proxy-hops": hops }).success;
	expect([1, 10, 0, 11, 1.5].map(parses)).toEqual([true, true, false, false, false]);
	expect(sourceSettings.parse({})).toEqual({ "trusted-proxies": [], "proxy-hops": 1 });
});

it("trusts an address entry as that one address only", () => {
	const { trusted } = proxiesOf(
		sourceSettings.parse({ "trusted-proxies": ["10.0.0.1", "2001:db8::1"] }),
	);
	expect(trusted.check("10.0.0.2", "ipv4")).toBe(false);
	expect(trusted.check("2001:db8::2", "ipv6")).toBe(false);
});

it("makes trusted proxies that cannot be changed", () => {
	expect(Object.isFrozen(proxiesOf(sourceSettings.parse({})))).toBe(true);
});

it("reads empty settings as no trusted proxy and one hop", () => {
	expect(sourceSettings.parse({})).toEqual({ "trusted-proxies": [], "proxy-hops": 1 });
});

it("takes an address list as trusted-proxies are taken, and answers whether an address is in it", () => {
	const schema = addressList();
	expect(schema.safeParse(["192.0.2.1", "10.0.0.0/8", "2001:db8::/32"]).success).toBe(true);
	for (const entry of ["10.0.0.0/08", "fe80::1%eth0", "10.0.0.0/33", "a.example"]) {
		expect(schema.safeParse([entry]).success, entry).toBe(false);
	}
	const list = addressesOf(["192.0.2.1", "10.0.0.0/8", "2001:db8::/32"]);
	expect(["192.0.2.1", "10.1.2.3", "2001:db8::9"].map((a) => list.has(a))).toEqual([
		true,
		true,
		true,
	]);
	expect(
		["192.0.2.2", "11.0.0.1", "2001:db9::1", "not an address"].map((a) => list.has(a)),
	).toEqual([false, false, false, false]);
	expect(addressesOf([]).has("192.0.2.1")).toBe(false);
	expect(() => addressesOf(["10.0.0.0/08"])).toThrow(TypeError);
	expect(Object.isFrozen(list)).toBe(true);
});
