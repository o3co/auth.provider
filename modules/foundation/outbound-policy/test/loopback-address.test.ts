import { describe, expect, it } from "vitest";
import {
	DestinationRefused,
	isLoopbackAddress,
	policyOf,
	policySettings,
} from "../src/contract.ts";
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

describe("an address written in the URL", () => {
	const policy = policyOf(
		policySettings.parse({
			"allow-any-public": true,
			"plain-loopback": ["127.0.0.1:8080"],
			"internal-hosts": ["10.0.0.1"],
		}),
	);
	const reasonOf = (url: string) => policy.explain(url)?.split(":")[0];

	it("is judged as written, so an IPv6 form that only carries 127/8 is no loopback", () => {
		// Listed as its IPv4 spelling, the pair matches; the reach is the address the URL names.
		expect(reasonOf("http://[::7f00:1]:8080/")).toBe("special-address");
		expect(reasonOf("http://[::ffff:0:7f00:1]:8080/")).toBe("special-address");
		expect(reasonOf("http://[::ffff:7f00:1]:8080/")).toBeUndefined();
		expect(reasonOf("http://127.0.0.1:8080/")).toBeUndefined();
	});

	it("keeps its written form beside the spelling lists compare", () => {
		const admitted = policy.admit("http://[::7f00:1]:8080/");
		expect([admitted.host, admitted.address]).toEqual(["127.0.0.1", "::7f00:1"]);
		expect(policy.admit("https://a.example/").address).toBeUndefined();
	});
});
