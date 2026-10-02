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
import { isSpecialUseAddress } from "#/net/special-use.mjs";

/**
 * The address ranges a caller-supplied URL must not resolve to. Pinned
 * against RFC 6890's table so a range dropped by accident is a failing test.
 */
describe("isSpecialUseAddress (RFC 6890)", () => {
	it("refuses every IPv4 special-use range", () => {
		for (const ip of [
			"0.0.0.0",
			"0.255.255.255",
			"10.0.0.1",
			"100.64.0.1",
			"100.127.255.254",
			"127.0.0.1",
			"127.255.255.255",
			"169.254.169.254", // the cloud metadata endpoint — the classic SSRF target
			"172.16.0.1",
			"172.31.255.254",
			"192.0.0.1",
			"192.0.2.10",
			"192.88.99.1",
			"192.168.1.1",
			"198.18.0.1",
			"198.19.255.254",
			"198.51.100.7",
			"203.0.113.9",
			"224.0.0.1",
			"239.255.255.255",
			"240.0.0.1",
			"255.255.255.255",
		]) {
			expect(isSpecialUseAddress(ip), ip).toBe(true);
		}
	});

	it("admits public IPv4 addresses", () => {
		for (const ip of [
			"1.1.1.1",
			"8.8.8.8",
			"93.184.216.34",
			"100.63.255.255",
			"172.32.0.1",
			"198.20.0.1",
		]) {
			expect(isSpecialUseAddress(ip), ip).toBe(false);
		}
	});

	it("refuses every IPv6 special-use range, the IPv4-mapped forms by their IPv4 half", () => {
		for (const ip of [
			"::",
			"::1",
			"::ffff:127.0.0.1",
			"::ffff:10.1.2.3",
			"::ffff:169.254.169.254",
			"::10.0.0.1",
			"64:ff9b::a00:1",
			"100::1",
			"2001::1",
			"2001:db8::1",
			"2002:c000:204::1",
			"fc00::1",
			"fd12:3456::1",
			"fe80::1",
			"ff02::1",
		]) {
			expect(isSpecialUseAddress(ip), ip).toBe(true);
		}
	});

	it("refuses the deprecated site-local range and the local-use translation prefix", () => {
		for (const ip of [
			"fec0::1", // site-local, RFC 3879
			"feff:ffff::1",
			"64:ff9b:1::a9fe:a9fe", // local-use IPv4/IPv6 translation, RFC 8215
			"64:ff9b:1:ffff::1",
		]) {
			expect(isSpecialUseAddress(ip), ip).toBe(true);
		}
		// The neighbours of both ranges stay public.
		expect(isSpecialUseAddress("64:ff9b:2::1")).toBe(false);
	});

	it("admits public IPv6 addresses, and IPv4-mapped public ones", () => {
		for (const ip of ["2606:4700:4700::1111", "2a00:1450:4001:80e::200e", "::ffff:8.8.8.8"]) {
			expect(isSpecialUseAddress(ip), ip).toBe(false);
		}
	});

	it("answers false for anything that is not an IP address — names are resolved first", () => {
		expect(isSpecialUseAddress("localhost")).toBe(false);
		expect(isSpecialUseAddress("example.com")).toBe(false);
		expect(isSpecialUseAddress("")).toBe(false);
	});
});

describe("isSpecialUseAddress — the spellings of an embedded IPv4 address", () => {
	it("judges a mapped or compatible address by its IPv4 half, however it was written", () => {
		// A DNS answer can carry any legal spelling. `::ffff:0:0/96` is
		// deliberately absent from the IPv6 table, so a spelling that fell
		// through to the IPv6 check would pass the SSRF guard.
		for (const address of [
			"::ffff:10.0.0.1",
			"::ffff:0a00:0001",
			"0:0:0:0:0:ffff:10.0.0.1",
			"0:0:0:0:0:ffff:0a00:0001",
			"::FFFF:0A00:0001",
			"::ffff:127.0.0.1",
			"::ffff:7f00:0001",
			"::ffff:169.254.169.254",
			"::10.0.0.1",
			"::0a00:0001",
		]) {
			expect(isSpecialUseAddress(address)).toBe(true);
		}
	});

	it("leaves a public embedded address alone, in the same spellings", () => {
		for (const address of [
			"::ffff:93.184.216.34",
			"::ffff:5db8:d822",
			"0:0:0:0:0:ffff:93.184.216.34",
		]) {
			expect(isSpecialUseAddress(address)).toBe(false);
		}
	});

	it("still answers for the addresses that embed nothing", () => {
		expect(isSpecialUseAddress("::1")).toBe(true);
		expect(isSpecialUseAddress("::")).toBe(true);
		expect(isSpecialUseAddress("fe80::1")).toBe(true);
		expect(isSpecialUseAddress("2606:2800:220:1:248:1893:25c8:1946")).toBe(false);
		expect(isSpecialUseAddress("not-an-address")).toBe(false);
	});
});

/** The first and last address of `prefix` (`net/length`), in the family's text form. */
const bounds = (prefix: string): [string, string] => {
	const [net = "", length = ""] = prefix.split("/");
	const bits = Number(length);
	if (net.includes(".")) {
		const value = net.split(".").reduce((acc, octet) => acc * 256 + Number(octet), 0);
		const size = 2 ** (32 - bits);
		const first = value - (value % size);
		const text = (n: number) =>
			[24, 16, 8, 0].map((shift) => Math.floor(n / 2 ** shift) % 256).join(".");
		return [text(first), text(first + size - 1)];
	}
	const [head = "", tail = ""] = net.split("::");
	const groups = (part: string) => (part === "" ? [] : part.split(":"));
	const all = [
		...groups(head),
		...Array.from({ length: 8 - groups(head).length - groups(tail).length }, () => "0"),
		...groups(tail),
	];
	const value = all.reduce((acc, group) => (acc << 16n) | BigInt(Number.parseInt(group, 16)), 0n);
	const host = (1n << BigInt(128 - bits)) - 1n;
	const text = (n: bigint) =>
		Array.from({ length: 8 }, (_, i) => ((n >> BigInt(112 - 16 * i)) & 0xffffn).toString(16)).join(
			":",
		);
	return [text(value & ~host), text(value | host)];
};

interface RegistryEntry {
	readonly prefix: string;
	/** The registry's "Globally Reachable" column; `undefined` where it is empty or N/A. */
	readonly globallyReachable: boolean | undefined;
	/** Why a globally reachable entry is refused anyway. */
	readonly refusedBecause?: string;
}

/**
 * The IANA special-purpose registries, as of 2026-10: every entry, with its
 * globally-reachable column. An entry that is not globally reachable must be
 * refused; one that is must be admitted unless a reason says otherwise.
 */
const REGISTRY: readonly RegistryEntry[] = [
	{ prefix: "0.0.0.0/8", globallyReachable: false },
	{ prefix: "0.0.0.0/32", globallyReachable: false },
	{ prefix: "10.0.0.0/8", globallyReachable: false },
	{ prefix: "100.64.0.0/10", globallyReachable: false },
	{ prefix: "127.0.0.0/8", globallyReachable: false },
	{ prefix: "169.254.0.0/16", globallyReachable: false },
	{ prefix: "172.16.0.0/12", globallyReachable: false },
	{ prefix: "192.0.0.0/24", globallyReachable: false },
	{ prefix: "192.0.0.0/29", globallyReachable: false },
	{ prefix: "192.0.0.8/32", globallyReachable: false },
	{ prefix: "192.0.0.9/32", globallyReachable: true, refusedBecause: "inside 192.0.0.0/24" },
	{ prefix: "192.0.0.10/32", globallyReachable: true, refusedBecause: "inside 192.0.0.0/24" },
	{ prefix: "192.0.0.170/32", globallyReachable: false },
	{ prefix: "192.0.0.171/32", globallyReachable: false },
	{ prefix: "192.0.2.0/24", globallyReachable: false },
	{ prefix: "192.31.196.0/24", globallyReachable: true },
	{ prefix: "192.52.193.0/24", globallyReachable: true },
	{ prefix: "192.88.99.0/24", globallyReachable: undefined },
	{ prefix: "192.88.99.2/32", globallyReachable: false },
	{ prefix: "192.168.0.0/16", globallyReachable: false },
	{ prefix: "192.175.48.0/24", globallyReachable: true },
	{ prefix: "198.18.0.0/15", globallyReachable: false },
	{ prefix: "198.51.100.0/24", globallyReachable: false },
	{ prefix: "203.0.113.0/24", globallyReachable: false },
	{ prefix: "240.0.0.0/4", globallyReachable: false },
	{ prefix: "255.255.255.255/32", globallyReachable: false },
	{ prefix: "::1/128", globallyReachable: false },
	{ prefix: "::/128", globallyReachable: false },
	{ prefix: "::ffff:0:0/96", globallyReachable: false },
	{ prefix: "64:ff9b::/96", globallyReachable: true, refusedBecause: "embeds any IPv4 address" },
	{ prefix: "64:ff9b:1::/48", globallyReachable: false },
	{ prefix: "100::/64", globallyReachable: false },
	{ prefix: "100:0:0:1::/64", globallyReachable: false },
	{ prefix: "2001::/23", globallyReachable: false },
	{ prefix: "2001::/32", globallyReachable: undefined },
	{ prefix: "2001:1::1/128", globallyReachable: true, refusedBecause: "inside 2001::/23" },
	{ prefix: "2001:1::2/128", globallyReachable: true, refusedBecause: "inside 2001::/23" },
	{ prefix: "2001:1::3/128", globallyReachable: true, refusedBecause: "inside 2001::/23" },
	{ prefix: "2001:2::/48", globallyReachable: false },
	{ prefix: "2001:3::/32", globallyReachable: true, refusedBecause: "inside 2001::/23" },
	{ prefix: "2001:4:112::/48", globallyReachable: true, refusedBecause: "inside 2001::/23" },
	{ prefix: "2001:10::/28", globallyReachable: undefined },
	{ prefix: "2001:20::/28", globallyReachable: true, refusedBecause: "inside 2001::/23" },
	{ prefix: "2001:30::/28", globallyReachable: true, refusedBecause: "inside 2001::/23" },
	{ prefix: "2001:db8::/32", globallyReachable: false },
	{ prefix: "2002::/16", globallyReachable: undefined },
	{ prefix: "2620:4f:8000::/48", globallyReachable: true },
	{ prefix: "3fff::/20", globallyReachable: false },
	{ prefix: "5f00::/16", globallyReachable: false },
	{ prefix: "fc00::/7", globallyReachable: false },
	{ prefix: "fe80::/10", globallyReachable: false },
];

describe("isSpecialUseAddress against the IANA special-purpose registries", () => {
	it.each(REGISTRY.map((entry) => [entry.prefix, entry] as const))(
		"%s: refused unless globally reachable",
		(_prefix, entry) => {
			const refused = entry.globallyReachable !== true || entry.refusedBecause !== undefined;
			for (const address of bounds(entry.prefix)) {
				expect(isSpecialUseAddress(address), address).toBe(refused);
			}
		},
	);

	it("refuses an entry whose column is empty or N/A, which no registry entry admits", () => {
		for (const entry of REGISTRY.filter((e) => e.globallyReachable === undefined)) {
			expect(isSpecialUseAddress(bounds(entry.prefix)[0])).toBe(true);
		}
	});

	it("refuses the IPv4-translated form (::ffff:0:0:0/96) whatever it embeds", () => {
		for (const address of [
			"::ffff:0:10.0.0.5",
			"::ffff:0:a00:5",
			"::ffff:0:5db8:d822",
			"0:0:0:0:ffff:0:808:808",
		]) {
			expect(isSpecialUseAddress(address), address).toBe(true);
		}
		// Its neighbour, the IPv4-mapped form, is still judged by its IPv4 half.
		expect(isSpecialUseAddress("::ffff:8.8.8.8")).toBe(false);
	});
});
