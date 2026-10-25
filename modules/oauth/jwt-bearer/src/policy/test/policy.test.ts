import { describe, expect, it } from "vitest";
import { issuersSetting } from "../../issuers/issuers.ts";
import { ceilingsOf, keepUntilOf, skewOf, verifierPolicy } from "../policy.ts";

const entryOf = (entry: Record<string, unknown>) => {
	const [read] = issuersSetting.parse([
		{ issuer: "https://a.example", subject: "as-is", "accept-any-subject": true, ...entry },
	]);
	if (!read) throw new Error("no entry");
	return read;
};
const limits = { "max-assertion-lifetime": 3600, "clock-skew": 30 };
const audiences = ["https://as.example", "https://as.example/oauth/token"];

describe("an issuer's policy", () => {
	it("verifies under its own lifetime and skew where it narrows the section's, else the section's", () => {
		expect(verifierPolicy(entryOf({}), limits, audiences)).toMatchObject({
			skewMs: 30_000,
			maxLifetimeMs: 3_600_000,
			expect: { aud: audiences },
		});
		const own = entryOf({ "max-assertion-lifetime": "10m", "clock-skew": "5s" });
		expect(verifierPolicy(own, limits, audiences)).toMatchObject({
			skewMs: 5000,
			maxLifetimeMs: 600_000,
		});
		expect(skewOf(own, limits)).toBe(5000);
	});

	it("takes its written keys' algorithms, else its own, else the defaults", () => {
		expect(verifierPolicy(entryOf({}), limits, audiences).algorithms).toEqual([
			"EdDSA",
			"ES256",
			"RS256",
		]);
		expect(
			verifierPolicy(entryOf({ algorithms: ["PS256"] }), limits, audiences).algorithms,
		).toEqual(["PS256"]);
	});

	it("keeps a spent assertion five minutes and a minute past its exp, whatever is set", () => {
		expect(keepUntilOf(1_000_000)).toBe(1_000_000 + 300_000 + 60_000);
	});

	it("holds tokens to its ceiling where it writes one, to none else", () => {
		expect(ceilingsOf(entryOf({}))).toEqual([]);
		expect(ceilingsOf(entryOf({ ceiling: { scopes: ["deploy"] } }))).toEqual([
			{ scopes: ["deploy"] },
		]);
	});
});
