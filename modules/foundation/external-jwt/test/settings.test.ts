import { expect, it } from "vitest";
import { algorithmsSetting, knownAlgorithms } from "../src/contract.ts";

it("gives a section the algorithms it takes: asymmetric ones alone, at least one, the caller's default where unwritten", () => {
	expect(knownAlgorithms).toEqual(expect.arrayContaining(["RS256", "PS256", "ES256", "EdDSA"]));
	const setting = algorithmsSetting(knownAlgorithms, ["RS256"]);
	expect(setting.parse(undefined)).toEqual(["RS256"]);
	expect(setting.parse(["ES256", "EdDSA"])).toEqual(["ES256", "EdDSA"]);
	for (const refused of [["none"], ["HS256"], ["RS256", "HS256"], []]) {
		expect(setting.safeParse(refused).success, String(refused)).toBe(false);
	}
	// A default outside the algorithms given is refused, as one the operator wrote is.
	expect(algorithmsSetting(["RS256"], ["ES256"]).safeParse(undefined).success).toBe(false);
});
