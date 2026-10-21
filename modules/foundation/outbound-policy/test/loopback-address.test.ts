import { describe, expect, it } from "vitest";
import { DestinationRefused, policyOf, policySettings } from "../src/contract.ts";
import { admitAddresses } from "../src/policy.ts";

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

describe("a public address written in the URL", () => {
	const policy = policyOf(policySettings.parse({ "allow-any-public": true }));
	const reasonOf = (url: string) => policy.explain(url)?.split(":")[0];

	it("is refused in any IPv6 form that carries it, as a resolved answer is", () => {
		// 93.184.215.14: IANA's ::ffff:0:0/96 is refused whole, as for ::ffff:8.8.8.8 resolved.
		expect(reasonOf("https://93.184.215.14/")).toBeUndefined();
		for (const url of [
			"https://[::ffff:5db8:d70e]/",
			"https://[::5db8:d70e]/",
			"https://[::ffff:0:5db8:d70e]/",
		]) {
			expect(reasonOf(url), url).toBe("special-address");
		}
	});
});
