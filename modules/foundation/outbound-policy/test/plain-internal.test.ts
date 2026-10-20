import { configuredUrl } from "@mod/url-setting/testing";
import { describe, expect, it } from "vitest";
import {
	credentialRefusalText,
	DestinationRefused,
	policyOf,
	policySettings,
	type RefusalReason,
} from "../src/contract.ts";
import { admitAddresses, admitUrl, credentialRefusal, type Rules } from "../src/policy.ts";

const rules: Rules = {
	allow: [],
	anyPublic: true,
	deny: [],
	plainLoopback: [],
	internal: [],
	plainInternal: ["ledger.internal:9092"],
};
const reasonOf = (run: () => unknown): RefusalReason | "admitted" => {
	try {
		run();
		return "admitted";
	} catch (error) {
		if (error instanceof DestinationRefused) return error.reason;
		throw error;
	}
};
const own = configuredUrl("http://ledger.internal:9092/verify");

describe("plain http to a pair plain-internal names", () => {
	it("is taken only for the caller's own configured URL at that origin", () => {
		const admitted = admitUrl("http://ledger.internal:9092/verify", rules, { internal: own });
		expect([admitted.plain, admitted.plainInternal, admitted.internal]).toEqual([
			true,
			true,
			false,
		]);
		// No configured URL, or another origin's, is no operator's own reach.
		expect(reasonOf(() => admitUrl("http://ledger.internal:9092/verify", rules))).toBe("scheme");
		const other = configuredUrl("http://ledger.internal:9093/verify");
		expect(
			reasonOf(() => admitUrl("http://ledger.internal:9092/verify", rules, { internal: other })),
		).toBe("scheme");
		// A pair not listed, though the URL is the caller's own.
		const unlisted = configuredUrl("http://other.internal:9092/x");
		expect(
			reasonOf(() => admitUrl("http://other.internal:9092/x", rules, { internal: unlisted })),
		).toBe("scheme");
	});

	it("is never taken where an outside party chose the destination, though the narrower also names it", () => {
		expect(
			reasonOf(() =>
				admitUrl("http://ledger.internal:9092/verify", rules, {
					internal: own,
					outsideChosen: true,
				}),
			),
		).toBe("scheme");
	});

	it("reaches a pair whose host is denied or not allowed no more than any other", () => {
		expect(
			reasonOf(() =>
				admitUrl(
					"http://ledger.internal:9092/verify",
					{ ...rules, deny: ["ledger.internal"] },
					{ internal: own },
				),
			),
		).toBe("denied");
		expect(
			reasonOf(() =>
				admitUrl(
					"http://ledger.internal:9092/verify",
					{ ...rules, anyPublic: false, allow: [] },
					{ internal: own },
				),
			),
		).toBe("not-allowed");
	});
});

describe("the addresses of a plain-internal pair", () => {
	const reach = { loopback: false, internal: false, plainInternal: true };
	const addresses = (list: readonly string[]) => reasonOf(() => admitAddresses(list, reach));

	it("are taken only where every one is private, 100.64/10 among them", () => {
		for (const list of [
			["10.1.2.3"],
			["172.16.0.1", "192.168.1.1"],
			["100.64.0.1"],
			["fd12:3456::1"],
			["::ffff:10.1.2.3"],
		]) {
			expect(addresses(list), list.join()).toBe("admitted");
		}
	});

	it("are refused as plain-public where one is public, in either order", () => {
		expect(addresses(["10.1.2.3", "93.184.216.34"])).toBe("plain-public");
		expect(addresses(["93.184.216.34", "10.1.2.3"])).toBe("plain-public");
		expect(addresses(["2606:4700::1111"])).toBe("plain-public");
	});

	it("are refused as special where none was answered, or one is loopback, link-local, metadata or NAT64", () => {
		for (const list of [
			[],
			["127.0.0.1"],
			["::1"],
			["169.254.169.254"],
			["fe80::1"],
			["100.100.100.200"],
			["::ffff:100.100.100.200"],
			["fd00:ec2::254"],
			["64:ff9b::a01:203"],
			["10.1.2.3", "169.254.169.254"],
		]) {
			expect(addresses(list), list.join()).toBe("special-address");
		}
	});

	it("are checked again on every request, so a name that turns public is refused", () => {
		const policy = policyOf(
			policySettings.parse({
				"allow-any-public": true,
				"plain-internal": ["ledger.internal:9092"],
			}),
		);
		const admitted = policy.admit("http://ledger.internal:9092/verify", { internal: own });
		expect(reasonOf(() => policy.admitAddresses(["10.0.0.5"], admitted))).toBe("admitted");
		expect(reasonOf(() => policy.admitAddresses(["93.184.216.34"], admitted))).toBe("plain-public");
	});
});

describe("plain-internal in the settings", () => {
	it("takes host:port pairs, none unless set, and refuses one plain-loopback also names however spelled", () => {
		expect(policySettings.parse({ "allow-any-public": true })["plain-internal"]).toEqual([]);
		const both = policySettings.safeParse({
			"allow-any-public": true,
			"plain-loopback": ["LOCALHOST.:8080"],
			"plain-internal": ["localhost:8080"],
		});
		expect(both.success).toBe(false);
		expect(both.error?.issues.map((issue) => issue.path.join("."))).toEqual(["plain-internal"]);
		expect(
			policySettings.safeParse({ "allow-any-public": true, "plain-internal": ["a.internal"] })
				.success,
		).toBe(false);
	});

	it("says what to set where plain http is refused, and why a public answer is", () => {
		const policy = policyOf(policySettings.parse({ "allow-any-public": true }));
		expect(policy.explain("http://ledger.internal:9092/x", { internal: own })).toContain(
			"outbound.plain-internal",
		);
	});
});

describe("a credential to a plain-internal pair", () => {
	it("goes there as to a named plain-loopback pair, at one origin", () => {
		expect(credentialRefusal(["http://ledger.internal:9092/a"], [], ["ledger.internal:9092"])).toBe(
			undefined,
		);
		expect(credentialRefusal(["http://ledger.internal:9092/a"], [], [])).toBe("scheme");
		expect(
			credentialRefusal(
				["http://ledger.internal:9092/a", "http://localhost:8080/b"],
				["localhost:8080"],
				["ledger.internal:9092"],
			),
		).toBe("origins");
	});

	it("is refused in words that name both lists", () => {
		expect(credentialRefusalText("scheme")).toContain("outbound.plain-internal");
		expect(credentialRefusalText("scheme")).toContain("outbound.plain-loopback");
		expect(credentialRefusalText("origins")).toContain("one origin");
	});
});
