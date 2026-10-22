import { describe, expect, it } from "vitest";
import {
	carriedIPv4,
	isLoopbackAddress,
	isPrivateAddress,
	isSpecialAddress,
} from "../src/contract.ts";

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

describe("isSpecialAddress", () => {
	it("takes each special-purpose block whole, and none of its public neighbours", () => {
		expect([isSpecialAddress("93.184.216.34"), isSpecialAddress("2606:4700::1111")]).toEqual([
			false,
			false,
		]);
		for (const [block, { inside, outside }] of Object.entries(blocks)) {
			for (const address of inside)
				expect(isSpecialAddress(address), `${block}: ${address}`).toBe(true);
			for (const address of outside) {
				expect(isSpecialAddress(address), `${block}: ${address}`).toBe(false);
			}
		}
	});
});

describe("isPrivateAddress", () => {
	it("takes the private networks, IPv4 mapped into IPv6 as the IPv4 address", () => {
		for (const address of [
			"10.0.0.1",
			"172.31.255.255",
			"192.168.1.1",
			"100.64.0.1",
			"fd12:3456::1",
			"[fd12:3456::1]",
			"fd00:ec2::24",
			"fd00:a9fe:a9fe::2",
			"fd00:42::41",
			"fd00:42::43",
			"fd00:c1::a9fe:a9ff",
			"::ffff:10.0.0.1",
			"::ffff:a00:1",
		]) {
			expect(isPrivateAddress(address), address).toBe(true);
		}
	});

	it("refuses the cloud metadata addresses inside them, any other address, and IPv6 forms that only carry one", () => {
		for (const address of [
			"100.100.100.200",
			"::ffff:100.100.100.200",
			"fd00:ec2::254",
			"fd20:ce::254",
			"fd00:ec2::23",
			"[fd00:ec2::23]",
			"fd00:a9fe:a9fe::1",
			"FD00:A9FE:A9FE:0:0:0:0:1",
			"fd00:42::42",
			"[FD00:0042:0:0:0:0:0:0042]",
			"fd00:c1::a9fe:a9fe",
			"fd00:c1::169.254.169.254",
			"93.184.216.34",
			"127.0.0.1",
			"169.254.169.254",
			"fe80::1",
			"::a00:1",
			"::ffff:0:a00:1",
		]) {
			expect(isPrivateAddress(address), address).toBe(false);
		}
	});
});

describe("carriedIPv4", () => {
	it("reads the IPv4 address an IPv6 address carries, mapped, translated or compatible", () => {
		expect(["::ffff:a00:1", "::ffff:0:a00:1", "::a00:1"].map(carriedIPv4)).toEqual([
			"10.0.0.1",
			"10.0.0.1",
			"10.0.0.1",
		]);
		// ::1 is no IPv4 address carried; nor is any other IPv6 address, nor an IPv4 one.
		expect(["::1", "2001:db8::1", "10.0.0.1"].map(carriedIPv4)).toEqual([
			undefined,
			undefined,
			undefined,
		]);
	});
});

describe("isLoopbackAddress", () => {
	it("takes an address that reaches loopback, however written", () => {
		for (const address of [
			"127.0.0.1",
			"127.255.255.254",
			"::1",
			"[::1]",
			"0:0:0:0:0:0:0:1",
			"::ffff:127.0.0.1",
			"[::ffff:7f00:1]",
			"::FFFF:127.1.2.3",
		]) {
			expect(isLoopbackAddress(address), address).toBe(true);
		}
	});

	it("refuses a name, another address, and an IPv6 form that carries 127/8 but is not routed to it", () => {
		for (const address of [
			"localhost",
			"",
			"127.1",
			"128.0.0.1",
			"::2",
			"fe80::1",
			"::127.0.0.1",
			"::ffff:0:127.0.0.1",
			"64:ff9b::7f00:1",
			"[127.0.0.1]",
		]) {
			expect(isLoopbackAddress(address), address).toBe(false);
		}
	});
});
