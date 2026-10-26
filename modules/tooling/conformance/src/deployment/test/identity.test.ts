import { describe, expect, it } from "vitest";
import { identityDifferences } from "../identity.ts";

describe("the instances of a deployment", () => {
	it("are one deployment only where each names the same issuer and keys", () => {
		const one = { issuer: "https://as.example", keys: ["k1", "k2"] };
		expect(identityDifferences([one, one])).toEqual([]);
		expect(identityDifferences([one, { ...one, issuer: "https://other.example" }])).toEqual([
			"instance 1 names the issuer https://other.example, instance 0 https://as.example",
		]);
		expect(identityDifferences([one, { ...one, keys: ["k1"] }])).toEqual([
			"instance 1 publishes the keys k1, instance 0 k1, k2",
		]);
	});

	it("are compared only where each publishes, and all alike: one that does not, beside one that does, differs", () => {
		expect(identityDifferences([null, null])).toEqual([]);
		expect(identityDifferences([{ issuer: "https://as.example", keys: [] }, null])).toEqual([
			"instance 1 publishes no metadata, instance 0 does",
		]);
	});
});
