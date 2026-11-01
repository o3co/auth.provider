import { expect, it } from "vitest";
import { factorBinding } from "../src/contract.ts";

it("offers the binding of a factor under mfa's name", () => {
	expect(factorBinding.label).toBe("mfa.factor-binding");
});
