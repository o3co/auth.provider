import { describe, expect, it } from "vitest";
import { factorKinds, firstBindingGates, secondFactorAmr, witnessing } from "../src/contract.ts";

describe("mfa-extensions", () => {
	it("offers the kinds by name, and the gates and the witnessing as many, under mfa's names", () => {
		expect([factorKinds.label, factorKinds.rule.multiplicity]).toEqual([
			"mfa.factor-kinds",
			"keyed",
		]);
		expect([firstBindingGates.label, firstBindingGates.rule.multiplicity]).toEqual([
			"mfa.first-binding-gates",
			"many",
		]);
		expect([witnessing.label, witnessing.rule.multiplicity]).toEqual(["mfa.witnessing", "many"]);
		expect(secondFactorAmr).toBe("mfa");
	});
});
