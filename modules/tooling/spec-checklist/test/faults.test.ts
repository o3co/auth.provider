import { describe, expect, it } from "vitest";
import { faultNames, isFaultName } from "../src/guarantee/faults.ts";

describe("faults", () => {
	it("names each fault once, in ASCII letters and digits, and knows no other", () => {
		expect(new Set(faultNames).size).toBe(faultNames.length);
		for (const name of faultNames) expect(name, name).toMatch(/^[A-Z][A-Za-z0-9]{0,2}$/);
		expect(faultNames).toEqual(
			expect.arrayContaining(["Pu", "Pd", "R", "L", "S", "Lr", "Lx", "F", "Fs", "C", "K", "H2"]),
		);
		expect(faultNames).toEqual(expect.arrayContaining(["M", "Ev", "R0", "Wt", "Nr", "Ta"]));
		// The boundary checks are no guarantee, so no fault a guarantee names.
		for (const boundary of ["T", "Fx"]) expect(isFaultName(boundary), boundary).toBe(false);
		expect(isFaultName("constructor")).toBe(false);
	});
});
