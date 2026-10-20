import { describe, expect, it } from "vitest";
import { DestinationRefused, isLoopbackAddress } from "../src/contract.ts";
import { admitAddresses } from "../src/policy.ts";

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

describe("a plain-loopback pair's addresses", () => {
	const reach = { loopback: true, internal: false, plainInternal: false };
	const refused = (addresses: readonly string[]) => {
		try {
			admitAddresses(addresses, reach);
			return "admitted";
		} catch (error) {
			if (error instanceof DestinationRefused) return error.reason;
			throw error;
		}
	};

	it("are taken where each reaches loopback, and refused where one is an IPv6 form that only carries it", () => {
		expect(refused(["127.0.0.1", "::1", "::ffff:127.0.0.1"])).toBe("admitted");
		expect(refused(["127.0.0.1", "::7f00:1"])).toBe("special-address");
		expect(refused(["::ffff:0:7f00:1"])).toBe("special-address");
	});
});
