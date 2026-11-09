import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { describe, expect, it } from "vitest";
import { trustOf } from "../src/choice/choice.ts";
import type { PathRules } from "../src/path.ts";
import { pathOf } from "../src/path.ts";
import { signatureAlgorithms } from "../src/signatures/signatures.ts";
import { ecKeys, hierarchy, issue, pssKeys, restated, rsaKeys } from "../src/testing.ts";

const now = Date.now();
/** The rules a test gives, with the anchors its trust is made of. */
type Given = PathRules & { readonly anchors: readonly Uint8Array[] };
const policyOf = (anchors: Uint8Array[], more: Partial<Given> = {}): Given => ({
	anchors,
	maxIntermediates: 4,
	minRsaBits: 2048,
	signatureAlgorithms,
	// As mtls holds a client's certificate: the leaf for client authentication, signing or key agreement.
	purpose: { ekus: ["1.3.6.1.5.5.7.3.2"], on: "leaf" },
	leafKeyUsage: 0x80 | 0x08,
	...more,
});
/** Refused, by the engine or by the path's rules, whichever comes first. */
const refusedAny = expect.not.stringMatching(/^path of/);
const reasonOf = async (leaf: Uint8Array, chain: Uint8Array[], policy: Given, at = now) => {
	const trust = trustOf({ anchors: policy.anchors, selfSignedAnchorsOnly: false });
	const read = await pathOf(leaf, chain, trust, policy, at);
	return read.kind === "path" ? `path of ${read.path.length}` : read.reason;
};

describe("path validation", () => {
	it("takes a leaf through the intermediates the client sent to a trusted anchor", async () => {
		const { root, intermediate, client } = await hierarchy();
		expect(await reasonOf(client.der, [intermediate.der], policyOf([root.der]))).toBe("path of 3");
		const plain = await hierarchy({ eku: undefined });
		expect(
			await reasonOf(plain.client.der, [plain.intermediate.der], policyOf([plain.root.der])),
		).toBe("path of 3");
	});

	it("refuses a path it cannot build to a trusted anchor, or one whose signatures or times do not hold, as pkijs's chain validation engine judges them [rfc8705-7.5-a]", async () => {
		const { root, intermediate, client } = await hierarchy();
		expect(await reasonOf(client.der, [], policyOf([root.der]))).toBe("path");
		// A root the client sends counts for nothing.
		expect(await reasonOf(client.der, [intermediate.der, root.der], policyOf([]))).toBe("path");
		const forged = await issue({ cn: "client", by: { ...intermediate, keys: await ecKeys() } });
		expect(await reasonOf(forged.der, [intermediate.der], policyOf([root.der]))).toBe("path");
		expect(
			await reasonOf(client.der, [intermediate.der], policyOf([root.der]), now + 2 * 86_400_000),
		).toBe("path");
		const early = await issue({ cn: "client", by: intermediate, notBefore: now + 3_600_000 });
		expect(await reasonOf(early.der, [intermediate.der], policyOf([root.der]))).toBe("path");
	});

	it("builds the path from the leaf sent alone, whatever else the chain holds", async () => {
		const { root, intermediate, client } = await hierarchy();
		const anchors = policyOf([root.der]);
		const stranger = await issue({ cn: "client", eku: ["1.3.6.1.5.5.7.3.2"] });
		for (const chain of [
			[stranger.der, client.der, intermediate.der],
			[client.der, intermediate.der],
			[intermediate.der, client.der],
		]) {
			expect(await reasonOf(stranger.der, chain, anchors)).toEqual(refusedAny);
		}
		expect(await reasonOf(client.der, [client.der, intermediate.der], anchors)).toBe("path of 3");
		// One that copies a trusted certificate's issuer and serial is not taken for it.
		const serial = client.certificate.serialNumber.valueBlock.valueDec;
		const copied = await issue({
			cn: "client",
			issuerName: "intermediate",
			serial,
			eku: ["1.3.6.1.5.5.7.3.2"],
		});
		expect(await reasonOf(copied.der, [client.der, intermediate.der], anchors)).toEqual(refusedAny);
		// A leaf whose signature is spoiled is not swapped for the good copy the chain carries.
		const copy = new pkijs.Certificate({
			schema: asn1js.fromBER(client.der.slice().buffer).result,
		});
		const signature = new Uint8Array(copy.signatureValue.valueBlock.valueHexView);
		signature[signature.length - 1] = (signature.at(-1) as number) ^ 1;
		copy.signatureValue = new asn1js.BitString({ valueHex: signature.buffer });
		const spoiled = new Uint8Array(copy.toSchema(true).toBER(false));
		expect(await reasonOf(spoiled, [intermediate.der, client.der], anchors)).toBe("path");
	});

	it("has the engine walk the chain chosen alone, though a certificate on it would sign as another's issuer too", async () => {
		const root = await issue({ cn: "root", ca: true, keyIds: true });
		const intermediate = await issue({ cn: "intermediate", by: root, ca: true, keyIds: true });
		// The leaf holds the root's key: by key identifier and signature, it reads as the intermediate's issuer too.
		const leaf = await issue({
			cn: "client",
			by: intermediate,
			keys: root.keys,
			keyIds: true,
			eku: ["1.3.6.1.5.5.7.3.2"],
		});
		const started = performance.now();
		expect(await reasonOf(leaf.der, [intermediate.der], policyOf([root.der]))).toBe("path of 3");
		expect(performance.now() - started).toBeLessThan(1000);
	});

	it("takes an anchor without key identifiers whose name is written in another string type than the name below it gives", async () => {
		// The root's name a PrintableString, its intermediate's issuer name a UTF8String.
		const root = await issue({ cn: "root", ca: true, printableSubject: true });
		const intermediate = await issue({ cn: "intermediate", by: root, ca: true });
		const client = await issue({ cn: "client", by: intermediate, eku: ["1.3.6.1.5.5.7.3.2"] });
		expect(await reasonOf(client.der, [intermediate.der], policyOf([root.der]))).toBe("path of 3");
	});

	it("refuses a weak signature, a small RSA key, or an unknown critical extension anywhere on the path", async () => {
		const { root, intermediate } = await hierarchy();
		const anchors = policyOf([root.der]);
		const sha1 = await issue({ cn: "client", by: intermediate, hash: "SHA-1" });
		expect(await reasonOf(sha1.der, [intermediate.der], anchors)).toEqual(refusedAny);
		for (const hash of ["SHA-1", "SHA-256"] as const) {
			const signer = await issue({ cn: "pss", by: root, ca: true, keys: await pssKeys(hash) });
			const signed = await issue({ cn: "client", by: signer, hash });
			expect(await reasonOf(signed.der, [signer.der], anchors)).toBe(
				hash === "SHA-1" ? "signature algorithm" : "path of 3",
			);
		}
		const small = await issue({ cn: "client", by: intermediate, keys: await rsaKeys(1024) });
		expect(await reasonOf(small.der, [intermediate.der], anchors)).toBe("rsa key too small");
		const weakSigner = await issue({ cn: "intermediate", by: root, ca: true, hash: "SHA-1" });
		const under = await issue({ cn: "client", by: weakSigner, eku: ["1.3.6.1.5.5.7.3.2"] });
		expect(await reasonOf(under.der, [weakSigner.der], anchors)).toBe("signature algorithm");
		const critical = await issue({ cn: "client", by: intermediate, criticalUnknown: true });
		expect(await reasonOf(critical.der, [intermediate.der], anchors)).toEqual(refusedAny);
	});

	it("refuses a signature its policy leaves out, the anchor's own aside", async () => {
		const { root, intermediate } = await hierarchy();
		const signed = await issue({ cn: "client", by: intermediate, hash: "SHA-384" });
		const narrowed = policyOf([root.der], { signatureAlgorithms: ["ecdsa-sha256"] });
		expect(await reasonOf(signed.der, [intermediate.der], narrowed)).toBe("signature algorithm");
		const taking = policyOf([root.der], { signatureAlgorithms: ["ecdsa-sha384"] });
		expect(await reasonOf(signed.der, [intermediate.der], taking)).toBe("signature algorithm");
		const both = policyOf([root.der], { signatureAlgorithms: ["ecdsa-sha256", "ecdsa-sha384"] });
		expect(await reasonOf(signed.der, [intermediate.der], both)).toBe("path of 3");
		const anchor = await issue({ cn: "root", ca: true, hash: "SHA-384" });
		const under = await issue({ cn: "client", by: anchor });
		const anchored = policyOf([anchor.der], { signatureAlgorithms: ["ecdsa-sha256"] });
		expect(await reasonOf(under.der, [], anchored)).toBe("path of 2");
	});

	it("refuses a signature stated as another algorithm than it was signed by, or as one of another family than its signer's key", async () => {
		const root = await issue({ cn: "root", ca: true });
		const intermediate = await issue({ cn: "int", by: root, ca: true, keys: await rsaKeys(2048) });
		const client = await issue({ cn: "client", by: intermediate, eku: ["1.3.6.1.5.5.7.3.2"] });
		const policy = policyOf([root.der]);
		expect(await reasonOf(client.der, [intermediate.der], policy)).toBe("path of 3");
		const asEcdsa = restated("certificate", client.der, "1.2.840.10045.4.3.2");
		// node checks the signature by the algorithm stated, so it is no issuer's: no path.
		expect(await reasonOf(asEcdsa, [intermediate.der], policy)).toBe("path");
	});

	it("counts an RSA key's bits from its first, however many zero bytes its encoding puts before them", async () => {
		const { root, intermediate } = await hierarchy();
		const padded = async (bits: number, zeros: number) => {
			const leaf = await issue({
				cn: "client",
				by: intermediate,
				eku: ["1.3.6.1.5.5.7.3.2"],
				keys: await rsaKeys(bits),
			});
			const cert = new pkijs.Certificate({
				schema: asn1js.fromBER(leaf.der.slice().buffer).result,
			});
			const key = cert.subjectPublicKeyInfo.parsedKey as pkijs.RSAPublicKey;
			const modulus = [...new Array(zeros).fill(0), ...key.modulus.valueBlock.valueHexView];
			const spki = new asn1js.Sequence({
				value: [new asn1js.Integer({ valueHex: new Uint8Array(modulus) }), key.publicExponent],
			});
			cert.subjectPublicKeyInfo.subjectPublicKey = new asn1js.BitString({
				valueHex: spki.toBER(false),
			});
			await cert.sign(intermediate.keys.privateKey, "SHA-256");
			const der = new Uint8Array(cert.toSchema(true).toBER(false));
			return reasonOf(der, [intermediate.der], policyOf([root.der]));
		};
		expect(await padded(2048, 1)).toBe("path of 3");
		expect(await padded(2040, 2)).toBe("rsa key too small");
		expect(await padded(2032, 4)).toBe("rsa key too small");
	});

	it("refuses a certificate on the path with an extension that does not parse, critical or not", async () => {
		const { root, intermediate } = await hierarchy();
		const anchors = policyOf([root.der]);
		for (const id of ["2.5.29.19", "2.5.29.15", "2.5.29.30", "2.5.29.17"]) {
			for (const critical of [true, false]) {
				const garbled = { id, critical };
				const leaf = await issue({ cn: "client", by: intermediate, garbled });
				const reason = await reasonOf(leaf.der, [intermediate.der], anchors);
				// node may read such a certificate as no issuer's before the rules do: refused either way.
				expect(["malformed extension", "path"], `${id} ${critical}`).toContain(reason);
			}
		}
		const inhibit = { id: "2.5.29.54", critical: true, value: new asn1js.Null().toBER(false) };
		const notAsn1 = { id: "2.5.29.19", critical: true, value: new Uint8Array([0xff]).buffer };
		for (const garbled of [inhibit, notAsn1]) {
			const leaf = await issue({ cn: "client", by: intermediate, garbled });
			expect(["malformed extension", "path"]).toContain(
				await reasonOf(leaf.der, [intermediate.der], anchors),
			);
		}
		const fine = {
			id: "2.5.29.54",
			critical: false,
			value: new asn1js.Integer({ value: 1 }).toBER(false),
		};
		const held = await issue({ cn: "client", by: intermediate, garbled: fine });
		expect(await reasonOf(held.der, [intermediate.der], anchors)).toBe("path of 3");
		const constrained = await issue({
			cn: "intermediate",
			by: root,
			ca: true,
			garbled: { id: "2.5.29.30", critical: true },
		});
		const under = await issue({ cn: "client", by: constrained });
		expect(["malformed extension", "path"]).toContain(
			await reasonOf(under.der, [constrained.der], anchors),
		);
	});

	it("holds the leaf to a client certificate, and every issuer to a CA within its path length", async () => {
		const root = await issue({ cn: "root", ca: true, pathLen: 0 });
		const intermediate = await issue({ cn: "intermediate", by: root, ca: true });
		const client = await issue({ cn: "client", by: intermediate });
		expect(await reasonOf(client.der, [intermediate.der], policyOf([root.der]))).toEqual(
			refusedAny,
		);
		const open = await issue({ cn: "root", ca: true });
		const last = await issue({ cn: "intermediate", by: open, ca: true, pathLen: 0 });
		const direct = await issue({ cn: "client", by: last });
		expect(await reasonOf(direct.der, [last.der], policyOf([open.der]))).toBe("path of 3");
		const fine = await hierarchy();
		const anchors = policyOf([fine.root.der]);
		const ca = await issue({ cn: "client", by: fine.intermediate, ca: true });
		expect(await reasonOf(ca.der, [fine.intermediate.der], anchors)).toBe("leaf is a ca");
		const server = await issue({ cn: "client", by: fine.intermediate, eku: ["1.3.6.1.5.5.7.3.1"] });
		expect(await reasonOf(server.der, [fine.intermediate.der], anchors)).toBe("purpose");
		for (const issuer of [
			await issue({ cn: "intermediate", by: fine.root, ca: false }),
			await issue({ cn: "intermediate", by: fine.root, bare: true }),
		]) {
			const under = await issue({ cn: "client", by: issuer });
			expect(await reasonOf(under.der, [issuer.der], anchors)).toEqual(refusedAny);
		}
		expect(
			await reasonOf(
				fine.client.der,
				[fine.intermediate.der],
				policyOf([fine.root.der], { maxIntermediates: 0 }),
			),
		).toBe("too many intermediates");
		const one = policyOf([fine.root.der], { maxIntermediates: 1 });
		expect(await reasonOf(fine.client.der, [fine.intermediate.der], one)).toBe("path of 3");
	});

	it("holds a leaf's key usage, where it has one, to signing or key agreement", async () => {
		const { root, intermediate } = await hierarchy();
		const anchors = policyOf([root.der]);
		for (const [keyUsage, reason] of [
			[0x20, "purpose"],
			[0x02, "purpose"],
			[0x80, "path of 3"],
			[0x08, "path of 3"],
		] as const) {
			for (const eku of [["1.3.6.1.5.5.7.3.2"], undefined]) {
				const leaf = await issue({ cn: "client", by: intermediate, eku, keyUsage });
				const said = await reasonOf(leaf.der, [intermediate.der], anchors);
				expect(said, `${keyUsage} ${eku}`).toBe(reason);
			}
		}
	});

	it("counts no self-issued CA against a path length", async () => {
		const root = await issue({ cn: "root", ca: true, pathLen: 0 });
		// A rollover: the root's name on a new key, issued under the root.
		const rollover = await issue({ cn: "root", by: root, ca: true });
		const client = await issue({ cn: "client", by: rollover });
		expect(await reasonOf(client.der, [rollover.der], policyOf([root.der]))).toBe("path of 3");
		const below = await issue({ cn: "intermediate", by: rollover, ca: true });
		const under = await issue({ cn: "client", by: below });
		expect(await reasonOf(under.der, [below.der, rollover.der], policyOf([root.der]))).toBe(
			"path length",
		);
	});

	it("takes an anchor whatever it signed itself with, as only its key is trusted", async () => {
		const root = await issue({ cn: "root", ca: true, hash: "SHA-1" });
		const client = await issue({ cn: "client", by: root });
		expect(await reasonOf(client.der, [], policyOf([root.der]))).toBe("path of 2");
	});

	it("refuses what is not a certificate", async () => {
		const { root } = await hierarchy();
		expect(await reasonOf(new Uint8Array([48, 3, 2, 1, 1]), [], policyOf([root.der]))).toBe(
			"malformed",
		);
		expect(await reasonOf(new Uint8Array([1, 2, 3]), [], policyOf([root.der]))).toBe("malformed");
	});

	it("refuses a certificate holding a string that does not decode as malformed", async () => {
		const { root, intermediate, client } = await hierarchy();
		const garbled = new pkijs.Certificate({ schema: asn1js.fromBER(client.der).result });
		// A BMPString of an odd length, which asn1js 4 answers as a decode error, not a throw.
		const odd = new asn1js.BmpString({ valueHex: new Uint8Array([0, 0x41, 0]).buffer });
		garbled.subject = new pkijs.RelativeDistinguishedNames({
			typesAndValues: [new pkijs.AttributeTypeAndValue({ type: "2.5.4.3", value: odd })],
		});
		const der = new Uint8Array(garbled.toSchema(true).toBER(false));
		expect(asn1js.fromBER(der).offset).toBe(-1);
		expect(await reasonOf(der, [intermediate.der], policyOf([root.der]))).toBe("malformed");
	});

	it("takes a certificate in date past 2049, which RFC 5280 writes as GeneralizedTime", async () => {
		const root = await issue({ cn: "root", ca: true, notAfter: Date.UTC(2070, 0, 1) });
		const client = await issue({ cn: "client", by: root, notAfter: Date.UTC(2060, 0, 1) });
		// Read back from the DER issued: written as GeneralizedTime, for 2060.
		const written = new pkijs.Certificate({ schema: asn1js.fromBER(client.der).result }).notAfter;
		expect([written.type, written.value.getTime()]).toEqual([
			pkijs.TimeType.GeneralizedTime,
			Date.UTC(2060, 0, 1),
		]);
		expect(await reasonOf(client.der, [], policyOf([root.der]))).toBe("path of 2");
		const at2061 = Date.UTC(2061, 0, 1);
		expect(await reasonOf(client.der, [], policyOf([root.der]), at2061)).toEqual(refusedAny);
	});
});

describe("the rules a caller chooses", () => {
	const serverAuth = "1.3.6.1.5.5.7.3.1";
	const anyPurpose = "2.5.29.37.0";
	/** As outbound holds a server's path: every certificate, anchor included, for server authentication. */
	const serverRules = (anchors: Uint8Array[], more: Partial<Given> = {}) =>
		policyOf(anchors, {
			purpose: { ekus: [serverAuth, anyPurpose], on: "path" },
			leafKeyUsage: 0x80 | 0x08,
			ecCurves: ["P-256", "P-384", "P-521"],
			...more,
		});

	it("takes as many certificates sent as the intermediates allowed and one more, and refuses allowing more than 14", async () => {
		const { root, intermediate, client } = await hierarchy();
		const twelve = policyOf([root.der], { maxIntermediates: 12 });
		const padding = await Promise.all(Array.from({ length: 13 }, (_, n) => issue({ cn: `p${n}` })));
		const sent = (n: number) => [intermediate.der, ...padding.slice(0, n - 1).map((p) => p.der)];
		expect(await reasonOf(client.der, sent(13), twelve)).toBe("path of 3");
		expect(await reasonOf(client.der, sent(14), twelve)).toBe("path");
		const trust = trustOf({ anchors: [root.der], selfSignedAnchorsOnly: false });
		const fifteen = policyOf([root.der], { maxIntermediates: 15 });
		await expect(pathOf(client.der, [intermediate.der], trust, fifteen, now)).rejects.toThrow(
			TypeError,
		);
	});

	it("takes an EC key only on a curve taken, anchor included, and any curve where none is given", async () => {
		const root = await issue({ cn: "root", ca: true, keys: await ecKeys("P-384") });
		const leaf = await issue({ cn: "leaf", by: root, eku: [serverAuth] });
		expect(await reasonOf(leaf.der, [], serverRules([root.der]))).toBe("path of 2");
		const p256 = serverRules([root.der], { ecCurves: ["P-256"] });
		expect(await reasonOf(leaf.der, [], p256)).toBe("ec curve");
		const own = await issue({
			cn: "leaf",
			by: root,
			eku: [serverAuth],
			keys: await ecKeys("P-521"),
		});
		expect(await reasonOf(own.der, [], serverRules([root.der], { ecCurves: ["P-384"] }))).toBe(
			"ec curve",
		);
		expect(
			await reasonOf(
				own.der,
				[],
				policyOf([root.der], { purpose: { ekus: [serverAuth], on: "leaf" } }),
			),
		).toBe("path of 2");
	});

	it("holds every certificate's extended key usage, anchor included, to the purposes where asked, and the leaf's alone otherwise", async () => {
		const { root, intermediate, client } = await hierarchy({ eku: [serverAuth] });
		expect(await reasonOf(client.der, [intermediate.der], serverRules([root.der]))).toBe(
			"path of 3",
		);
		// An intermediate for client authentication alone.
		const clientOnly = await issue({
			cn: "intermediate",
			by: root,
			ca: true,
			eku: ["1.3.6.1.5.5.7.3.2"],
		});
		const under = await issue({ cn: "client", by: clientOnly, eku: [serverAuth] });
		expect(await reasonOf(under.der, [clientOnly.der], serverRules([root.der]))).toBe("purpose");
		// The same path, the leaf's alone held: taken.
		const leafOnly = serverRules([root.der], { purpose: { ekus: [serverAuth], on: "leaf" } });
		expect(await reasonOf(under.der, [clientOnly.der], leafOnly)).toBe("path of 3");
		// An anchor for client authentication alone.
		const anchor = await issue({ cn: "root", ca: true, eku: ["1.3.6.1.5.5.7.3.2"] });
		const below = await issue({ cn: "leaf", by: anchor, eku: [serverAuth] });
		expect(await reasonOf(below.der, [], serverRules([anchor.der]))).toBe("purpose");
		// anyExtendedKeyUsage is taken where the rules name it.
		const any = await issue({ cn: "root", ca: true, eku: [anyPurpose] });
		const leaf = await issue({ cn: "leaf", by: any, eku: [serverAuth] });
		expect(await reasonOf(leaf.der, [], serverRules([any.der]))).toBe("path of 2");
	});

	it("holds the anchor's RSA key to the fewest bits, as every certificate's on the path", async () => {
		const weak = await issue({ cn: "root", ca: true, keys: await rsaKeys(1024) });
		const leaf = await issue({ cn: "leaf", by: weak, eku: ["1.3.6.1.5.5.7.3.2"] });
		expect(await reasonOf(leaf.der, [], policyOf([weak.der]))).toBe("rsa key too small");
	});
});
