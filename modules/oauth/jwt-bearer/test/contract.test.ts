import { verifyAlgorithms } from "@mod/keys";
import { expect, it } from "vitest";
import { algorithms, type SignerKeys, takenAlgorithms } from "../src/contract.ts";

it("takes by default one algorithm for each kind of key, among every asymmetric one keys verifies", () => {
	expect([...algorithms]).toEqual(["EdDSA", "ES256", "RS256"]);
	expect(takenAlgorithms).toEqual(verifyAlgorithms);
	for (const alg of algorithms) expect(takenAlgorithms).toContain(alg);
});

it("lets a contribution declare that it answers each signer's own keys alone", () => {
	const declared: SignerKeys = {
		issuer: "https://devices.example",
		perSigner: true,
		keysOf: async () => ({ kind: "none" }),
	};
	const silent: SignerKeys = {
		issuer: "https://devices.example",
		keysOf: async () => ({ kind: "none" }),
	};
	expect([declared.perSigner, silent.perSigner]).toEqual([true, undefined]);
});
