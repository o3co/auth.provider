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
			if (DestinationRefused.is(error)) return error.reason;
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

describe("a plain-loopback pair", () => {
	const policy = policyOf(
		policySettings.parse({ "allow-any-public": true, "plain-loopback": ["crl.example:80"] }),
	);
	const fetched = (narrower: { outsideChosen?: true }, signed: boolean) => {
		try {
			const admitted = policy.admit(
				"http://crl.example/root.crl",
				{ hosts: ["crl.example"], ...narrower },
				signed,
			);
			policy.admitAddresses(["127.0.0.1"], admitted);
			return "admitted";
		} catch (error) {
			if (DestinationRefused.is(error)) return error.reason;
			throw error;
		}
	};

	it("is never reached by a URL an outside party chose, signed material included, only by one the operator's caller names", () => {
		expect(fetched({}, false)).toBe("admitted");
		expect(fetched({}, true)).toBe("admitted");
		// A URL a certificate chose, as for its CRL: public addresses alone.
		expect(fetched({ outsideChosen: true }, true)).toBe("special-address");
		expect(fetched({ outsideChosen: true }, false)).toBe("scheme");
	});
});
