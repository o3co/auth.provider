import { expect, it } from "vitest";
import { factorManaging } from "../src/contract.ts";

it("offers the managing of the factors under mfa's name", () => {
	expect(factorManaging.label).toBe("mfa.factor-managing");
});
