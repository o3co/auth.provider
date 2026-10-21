import { describe, expect, it } from "vitest";
import {
	DestinationRefused,
	policyOf,
	policySettings,
	type RefusalReason,
} from "../src/contract.ts";

/** The policy of these settings, the rest as an operator leaves them. */
const made = (settings: Record<string, unknown> = {}) =>
	policyOf(policySettings.parse({ "allow-any-public": true, ...settings }));
const reasonOf = (run: () => unknown): RefusalReason | "admitted" => {
	try {
		run();
		return "admitted";
	} catch (error) {
		if (DestinationRefused.is(error)) return error.reason;
		throw error;
	}
};

describe("a policy made from the operator's settings", () => {
	it("admits a URL as its settings say, and answers the addresses it checked, to connect to the first", () => {
		const policy = made({ deny: ["bad.example"] });
		expect(reasonOf(() => policy.admit("https://bad.example/"))).toBe("denied");
		const admitted = policy.admit("https://ok.example/");
		expect(policy.admitAddresses(["8.8.8.8", "93.184.216.34"], admitted)).toEqual([
			"8.8.8.8",
			"93.184.216.34",
		]);
		expect(reasonOf(() => policy.admitAddresses([], admitted))).toBe("special-address");
	});

	it("refuses an address a deny entry names, whatever name resolved to it, in IPv6 carrying it too", () => {
		const policy = made({ deny: ["93.184.216.34", "2001:db8::7", ".bad.example"] });
		const admitted = policy.admit("https://ok.example/");
		for (const addresses of [
			["93.184.216.34"],
			["8.8.8.8", "93.184.216.34"],
			["::ffff:93.184.216.34"],
			["::ffff:5db8:d822"],
			["2001:db8:0:0:0:0:0:7"],
		]) {
			expect(
				reasonOf(() => policy.admitAddresses(addresses, admitted)),
				addresses.join(),
			).toBe("denied");
		}
		// A name entry denies the URL's host alone; addresses another name resolved to stay reachable.
		expect(policy.admitAddresses(["8.8.8.8"], admitted)).toEqual(["8.8.8.8"]);
	});

	it("cuts a request at the caps a caller narrows, never widens, and at the signed cap for signed material", () => {
		const policy = made({
			timeout: "2s",
			"max-response-size": "1KiB",
			"signed-max-response-size": "4KiB",
		});
		expect(policy.limitsOf()).toEqual({ timeoutMs: 2000, maxBytes: 1024 });
		expect(policy.limitsOf({ timeoutMs: 500, maxBytes: 99_999 })).toEqual({
			timeoutMs: 500,
			maxBytes: 1024,
		});
		expect(policy.limitsOf({}, true)).toEqual({ timeoutMs: 2000, maxBytes: 4096 });
		for (const timeoutMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
			expect(() => policy.limitsOf({ timeoutMs })).toThrow(RangeError);
		}
	});

	it("explains a refusal with what to set, says where a credential may not go, and reads host lists", () => {
		const policy = made({ "allow-any-public": false, allow: ["idp.example"] });
		expect(policy.explain("https://other.example/")).toBe(
			"not-allowed: name the host in outbound.allow, or set outbound.allow-any-public",
		);
		expect(policy.explain("https://idp.example/")).toBeUndefined();
		expect(policy.credentialRefusal(["https://a.example/", "https://b.example/"])).toBe("origins");
		expect(policy.listed("keys.cdn.example", [".cdn.example"])).toBe(true);
	});
});

describe("the policy's settings", () => {
	it("refuses naming hosts in allow beside allow-any-public, and an entry that is not a host", () => {
		expect(
			policySettings.safeParse({ allow: ["a.example"], "allow-any-public": true }).success,
		).toBe(false);
		expect(policySettings.safeParse({ deny: ["*.example"] }).success).toBe(false);
	});
});
