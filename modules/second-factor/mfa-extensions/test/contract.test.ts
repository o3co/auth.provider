import { describe, expect, it } from "vitest";
import {
	type FactorKind,
	factorKinds,
	firstBindingGates,
	issuedWayBack,
	secondFactorAmr,
	witnessing,
} from "../src/contract.ts";

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

	it("tells a way back mfa issues itself, which no subject begins: one that does not count and guessing cannot beat", () => {
		const kind = (counts: boolean, guessable: boolean) =>
			({ kind: "k", amr: [], addsSecondFactor: false, counts, guessable }) as unknown as FactorKind;
		// The recovery codes' shape.
		expect(issuedWayBack(kind(false, false))).toBe(true);
		// A code by mail that adds no mfa: a way back, but one a subject binds.
		expect(issuedWayBack(kind(false, true))).toBe(false);
		expect(issuedWayBack(kind(true, true))).toBe(false);
		expect(issuedWayBack(kind(true, false))).toBe(false);
		// A kind that says nothing of guessing is held to the stricter side, as mfa takes it: no issued way back.
		expect(issuedWayBack({ counts: false } as unknown as FactorKind)).toBe(false);
	});
});
