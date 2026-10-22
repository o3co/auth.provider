import { expect, it } from "vitest";
import { factorReading } from "../src/contract.ts";

it("offers the reading of the factors under mfa's name", () => {
	expect(factorReading.label).toBe("mfa.factor-reading");
});
