import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { expect, it } from "vitest";
import { ecKeys, issue, rsaKeys } from "../../testing.ts";
import { fitsKey, isTaken, sameAlgorithm, signatureAlgorithms } from "../signatures.ts";

const pss = "1.2.840.113549.1.1.10";
const sha2 = (n: number) => `2.16.840.1.101.3.4.2.${n}`;
const sha1 = "1.3.14.3.2.26";

/** PSS over a hash, its mask MGF1 over `maskHash`, with the trailer given. */
const pssOf = (hash: string, maskHash = hash, trailerField = 1) => {
	const hashAlgorithm = new pkijs.AlgorithmIdentifier({ algorithmId: hash });
	const maskGenAlgorithm = new pkijs.AlgorithmIdentifier({
		algorithmId: "1.2.840.113549.1.1.8",
		algorithmParams: new pkijs.AlgorithmIdentifier({ algorithmId: maskHash }).toSchema(),
	});
	const params = new pkijs.RSASSAPSSParams({ hashAlgorithm, maskGenAlgorithm, trailerField });
	return new pkijs.AlgorithmIdentifier({ algorithmId: pss, algorithmParams: params.toSchema() });
};

it("takes PSS only over SHA-2 with MGF1 over the same hash and the one trailer, refusing its SHA-1 default and parameters that do not parse", () => {
	const all = (algorithm: pkijs.AlgorithmIdentifier) => isTaken(algorithm, signatureAlgorithms);
	for (const n of [1, 2, 3]) expect(all(pssOf(sha2(n)))).toBe(true);
	expect(all(pssOf(sha1))).toBe(false);
	expect(all(pssOf(sha2(1), sha1))).toBe(false);
	expect(all(pssOf(sha2(1), sha2(1), 2))).toBe(false);
	const bare = (params?: asn1js.AsnType) =>
		all(new pkijs.AlgorithmIdentifier({ algorithmId: pss, algorithmParams: params }));
	expect(bare()).toBe(false);
	expect(bare(new asn1js.Integer({ value: 1 }))).toBe(false);
	const hashOnly = new pkijs.RSASSAPSSParams({
		hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: sha2(1) }),
	});
	expect(bare(hashOnly.toSchema())).toBe(false);
});

it("takes SHA-2 RSA and ECDSA by identifier, and not their SHA-1 forms nor EdDSA, which the engine cannot verify", () => {
	const of = (algorithmId: string) =>
		isTaken(new pkijs.AlgorithmIdentifier({ algorithmId }), signatureAlgorithms);
	const taken = ["1.1.11", "1.1.12", "1.1.13"].map((id) => `1.2.840.113549.${id}`);
	taken.push(...["4.3.2", "4.3.3", "4.3.4"].map((id) => `1.2.840.10045.${id}`));
	expect(taken.map(of)).toEqual(taken.map(() => true));
	const refused = ["1.2.840.113549.1.1.5", "1.2.840.10045.4.1", "1.3.101.112", "1.3.101.113"];
	expect(refused.map(of)).toEqual(refused.map(() => false));
});

it("takes an algorithm only where it is named among those taken", () => {
	const ecdsa384 = new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.840.10045.4.3.3" });
	expect(isTaken(ecdsa384, ["ecdsa-sha384"])).toBe(true);
	expect(isTaken(ecdsa384, ["ecdsa-sha256", "ecdsa-sha512"])).toBe(false);
	expect(isTaken(pssOf(sha2(1)), ["rsa-pss-sha256"])).toBe(true);
	expect(isTaken(pssOf(sha2(1)), ["rsa-pkcs1-sha256", "rsa-pss-sha384"])).toBe(false);
});

it("fits an algorithm only to a key of its family: RSA and PSS to an RSA key, ECDSA to an EC key", async () => {
	const rsa = (await issue({ cn: "rsa", keys: await rsaKeys(2048) })).certificate;
	const ec = (await issue({ cn: "ec", keys: await ecKeys() })).certificate;
	const pkcs1 = new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.840.113549.1.1.11" });
	const ecdsa = new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.840.10045.4.3.2" });
	const fits = (a: pkijs.AlgorithmIdentifier, c: pkijs.Certificate) =>
		fitsKey(a, c.subjectPublicKeyInfo);
	expect([fits(pkcs1, rsa), fits(pssOf(sha2(1)), rsa), fits(ecdsa, ec)]).toEqual([
		true,
		true,
		true,
	]);
	expect([fits(pkcs1, ec), fits(pssOf(sha2(1)), ec), fits(ecdsa, rsa)]).toEqual([
		false,
		false,
		false,
	]);
	expect(fits(new pkijs.AlgorithmIdentifier({ algorithmId: "1.3.101.112" }), ec)).toBe(false);
});

it("tells the algorithm signed inside from a different one stated beside the signature", () => {
	const ecdsa = new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.840.10045.4.3.2" });
	const again = new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.840.10045.4.3.2" });
	expect(sameAlgorithm(ecdsa, again)).toBe(true);
	expect(
		sameAlgorithm(ecdsa, new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.840.10045.4.3.3" })),
	).toBe(false);
	expect(sameAlgorithm(pssOf(sha2(1)), pssOf(sha2(1), sha2(2)))).toBe(false);
});
