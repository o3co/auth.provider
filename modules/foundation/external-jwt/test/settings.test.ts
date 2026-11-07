import { expect, it } from "vitest";
import { algorithmsSetting, boundAlgorithm, knownAlgorithms } from "../src/contract.ts";
import { testSigner } from "../src/testing.ts";

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

it("tells the one algorithm a key is read under among those allowed, as a verifier reads it, or none", async () => {
	const { jwk: rsa } = await testSigner("RS256");
	const { jwk: p256 } = await testSigner("ES256");
	const { jwk: ed } = await testSigner("EdDSA");
	expect(boundAlgorithm(rsa, ["RS256", "ES256"])).toBe("RS256");
	expect(boundAlgorithm(p256, ["RS256", "ES256", "ES384"])).toBe("ES256");
	expect(boundAlgorithm(ed, ["RS256", "EdDSA"])).toBe("EdDSA");
	expect(boundAlgorithm({ ...rsa, alg: "PS256" }, ["RS256", "PS256"])).toBe("PS256");
	// Two allowed for its kind and none named, an algorithm named that is not allowed, or none that fits.
	expect(boundAlgorithm(rsa, ["RS256", "PS256"])).toBeUndefined();
	expect(boundAlgorithm({ ...rsa, alg: "RS512" }, ["RS256"])).toBeUndefined();
	expect(boundAlgorithm({ ...p256, alg: "RS256" }, ["RS256", "ES256"])).toBeUndefined();
	expect(boundAlgorithm(ed, ["RS256", "ES256"])).toBeUndefined();
});
