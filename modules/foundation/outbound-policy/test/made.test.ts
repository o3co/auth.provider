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

	it("names the plain lists too in a plain http URL's first refusal, so one refusal says every key it needs", () => {
		const policy = made({ "allow-any-public": false, allow: ["idp.example"] });
		expect(policy.explain("http://localhost:8080/")).toBe(
			"not-allowed: name the host in outbound.allow, or set outbound.allow-any-public; plain http also needs its host:port in outbound.plain-loopback, or, for a URL of your own configuration on a private network, in outbound.plain-internal",
		);
		// https asks nothing of the plain lists.
		expect(policy.explain("https://other.example/")).toBe(
			"not-allowed: name the host in outbound.allow, or set outbound.allow-any-public",
		);
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

	it("reads a pair's IPv6 host in brackets alone", () => {
		for (const key of ["plain-loopback", "plain-internal"]) {
			expect(policySettings.safeParse({ [key]: ["[::1]:80"] }).success, key).toBe(true);
			expect(policySettings.safeParse({ [key]: ["::1:80"] }).success, key).toBe(false);
		}
	});

	it("refuses a host its one reading refuses, in pairs and in allow and deny alike", () => {
		for (const host of ["a..b", "a_b", "10.5", "127.1", "host."]) {
			for (const key of ["allow", "deny"]) {
				expect(policySettings.safeParse({ [key]: [host] }).success, `${key} ${host}`).toBe(false);
			}
			for (const key of ["plain-loopback", "plain-internal"]) {
				const pair = `${host}:80`;
				expect(policySettings.safeParse({ [key]: [pair] }).success, `${key} ${pair}`).toBe(false);
			}
		}
		// An IPv6 address with a zone has no canonical form, so no request's address is ever it.
		for (const key of ["allow", "deny"]) {
			for (const host of ["::1%eth0", "2606:4700:4700::1111%eth0", "[::1%eth0]"]) {
				expect(policySettings.safeParse({ [key]: [host] }).success, `${key} ${host}`).toBe(false);
			}
		}
		for (const key of ["plain-loopback", "plain-internal"]) {
			expect(policySettings.safeParse({ [key]: ["[::1%eth0]:443"] }).success, key).toBe(false);
		}
		// A name in another script, its marks included, is read as the URL parser maps a host.
		for (const key of ["allow", "deny", "internal-hosts"]) {
			expect(policySettings.safeParse({ [key]: ["कि.example"] }).success, key).toBe(true);
		}
		expect(policySettings.safeParse({ "internal-hosts": ["fe80::1%eth0"] }).success).toBe(false);
		const mapped = policyOf(policySettings.parse({ allow: ["कि.example"] }));
		expect(mapped.explain("https://xn--11b8f.example/")).toBeUndefined();
		// A dot leading a name covers the names under it in a host list; a pair names one host.
		expect(policySettings.safeParse({ allow: [".a"] }).success).toBe(true);
		expect(policySettings.safeParse({ "plain-loopback": [".a:80"] }).success).toBe(false);
	});
});
