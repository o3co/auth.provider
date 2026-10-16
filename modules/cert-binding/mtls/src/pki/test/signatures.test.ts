import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { expect, it } from "vitest";
import { isStrong } from "../signatures.ts";

const pss = "1.2.840.113549.1.1.10";

it("takes PSS only over SHA-2, refusing its SHA-1 default and parameters that do not parse", () => {
	const over = (params?: asn1js.AsnType) =>
		isStrong(new pkijs.AlgorithmIdentifier({ algorithmId: pss, algorithmParams: params }));
	for (const hash of ["1", "2", "3"]) {
		const hashAlgorithm = new pkijs.AlgorithmIdentifier({
			algorithmId: `2.16.840.1.101.3.4.2.${hash}`,
		});
		expect(over(new pkijs.RSASSAPSSParams({ hashAlgorithm }).toSchema())).toBe(true);
	}
	expect(over()).toBe(false);
	expect(over(new asn1js.Integer({ value: 1 }))).toBe(false);
});

it("takes SHA-2 RSA and ECDSA by identifier, and not their SHA-1 forms nor EdDSA, which the engine cannot verify", () => {
	const of = (algorithmId: string) => isStrong(new pkijs.AlgorithmIdentifier({ algorithmId }));
	const taken = ["1.1.11", "1.1.12", "1.1.13"].map((id) => `1.2.840.113549.${id}`);
	taken.push(...["4.3.2", "4.3.3", "4.3.4"].map((id) => `1.2.840.10045.${id}`));
	expect(taken.map(of)).toEqual(taken.map(() => true));
	const refused = ["1.2.840.113549.1.1.5", "1.2.840.10045.4.1", "1.3.101.112", "1.3.101.113"];
	expect(refused.map(of)).toEqual(refused.map(() => false));
});
