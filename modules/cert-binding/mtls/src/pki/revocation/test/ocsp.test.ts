import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { describe, expect, it } from "vitest";
import {
	ecKeys,
	hierarchy,
	type Issued,
	type Issuing,
	issue,
	ocspOf,
	rsaKeys,
} from "../../test/authority.ts";
import { type Asked, judgeOcsp, ocspRequestOf, ocspUrlsOf } from "../ocsp.ts";

const ocspSigning = "1.3.6.1.5.5.7.3.9";
const asked = (more: Partial<Asked> = {}) => ({
	now: Date.now(),
	skewMs: 300_000,
	freshMs: 600_000,
	minRsaBits: 2048,
	...more,
});
const nonce = new Uint8Array(16).fill(7);

async function setUp() {
	const { root, intermediate, client } = await hierarchy();
	const reasonOf = async (der: Uint8Array, more: Partial<Asked> = {}) => {
		const judged = await judgeOcsp(der, client.certificate, intermediate.certificate, asked(more));
		return judged.kind === "unusable" ? judged.reason : judged.kind;
	};
	const responder = (more: Partial<Issuing> = {}) =>
		issue({ cn: "responder", by: intermediate, eku: [ocspSigning], ...more });
	return { root, intermediate, client, reasonOf, responder };
}

describe("judging an OCSP response", () => {
	it("tells good, revoked and unknown from the issuer, named or keyed, until the next update", async () => {
		const { intermediate, client, reasonOf } = await setUp();
		const base = { cert: client, issuer: intermediate };
		for (const status of ["good", "revoked", "unknown"] as const) {
			expect(await reasonOf(await ocspOf({ ...base, status }))).toBe(status);
			expect(await reasonOf(await ocspOf({ ...base, status, byKey: true }))).toBe(status);
		}
		const next = Date.now() + 1_800_000;
		const judged = await judgeOcsp(
			await ocspOf({ ...base, nextUpdate: next }),
			client.certificate,
			intermediate.certificate,
			asked(),
		);
		expect(judged.kind === "good" && Math.abs(judged.until - next) < 1000).toBe(true);
		expect(judged).not.toHaveProperty("responder");
	});

	it("takes a responder the issuer delegated to, and hands it back to be checked unless it says not to", async () => {
		const { intermediate, client, responder } = await setUp();
		const judge = async (by: Issued, byKey = false) =>
			judgeOcsp(
				await ocspOf({ cert: client, issuer: intermediate, by, certs: [by], byKey }),
				client.certificate,
				intermediate.certificate,
				asked(),
			);
		const delegated = await responder();
		const judged = await judge(delegated);
		expect(judged.kind).toBe("good");
		expect(
			judged.kind === "good" && judged.responder?.subject.isEqual(delegated.certificate.subject),
		).toBe(true);
		expect(await judge(delegated, true)).toMatchObject({ kind: "good" });
		expect(await judge(await responder({ noCheck: true }))).not.toHaveProperty("responder");
		const garbled = await judge(await responder({ noCheck: "garbled" }));
		expect(garbled.kind === "good" && garbled.responder !== undefined).toBe(true);
	});

	it("ends an answer when its delegated responder does, if that comes before the next update", async () => {
		const { intermediate, client, responder } = await setUp();
		const ends = Math.floor((Date.now() + 600_000) / 1000) * 1000;
		const until = async (nextUpdate: number) => {
			const by = await responder({ notAfter: ends });
			const judged = await judgeOcsp(
				await ocspOf({ cert: client, issuer: intermediate, by, certs: [by], nextUpdate }),
				client.certificate,
				intermediate.certificate,
				asked(),
			);
			return judged.kind === "good" ? judged.until : judged.kind;
		};
		expect(await until(Date.now() + 3_600_000)).toBe(ends);
		const sooner = Math.floor((Date.now() + 300_000) / 1000) * 1000;
		expect(await until(sooner)).toBe(sooner);
	});

	it("takes no responder the issuer did not delegate to, nor one out of date, nor one not given", async () => {
		const { root, intermediate, client, reasonOf, responder } = await setUp();
		const base = { cert: client, issuer: intermediate };
		const answer = async (by: Issued, certs: Issued[] = [by]) => ocspOf({ ...base, by, certs });
		expect(await reasonOf(await answer(await responder({ eku: ["1.3.6.1.5.5.7.3.2"] })))).toBe(
			"signer",
		);
		expect(await reasonOf(await answer(await responder({ by: root })))).toBe("signer");
		const stranger = await issue({ cn: "intermediate", keys: await ecKeys(), eku: [ocspSigning] });
		const posing = await issue({ cn: "responder", by: stranger, eku: [ocspSigning] });
		expect(await reasonOf(await answer(posing))).toBe("signer");
		expect(await reasonOf(await answer(await responder({ notAfter: Date.now() - 1000 })))).toBe(
			"signer",
		);
		const early = await responder({ notBefore: Date.now() + 3_600_000 });
		expect(await reasonOf(await answer(early))).toBe("signer");
		const misnamed = await responder({ issuerName: "elsewhere" });
		expect(await reasonOf(await answer(misnamed))).toBe("signer");
		expect(await reasonOf(await answer(await responder(), []))).toBe("signer");
		expect(await reasonOf(await answer(await responder({ hash: "SHA-1" })))).toBe("signer");
		// Held to the key rules of a certificate on the path.
		const enciphering = await responder({ keyUsage: 0x20 });
		expect(await reasonOf(await answer(enciphering))).toBe("signer");
		expect(await reasonOf(await answer(await responder({ keyUsage: 0x80 })))).toBe("good");
		const small = await responder({ keys: await rsaKeys(1024) });
		expect(await reasonOf(await answer(small))).toBe("signer");
		expect(await reasonOf(await answer(await responder({ keys: await rsaKeys(2048) })))).toBe(
			"good",
		);
		for (const id of ["2.5.29.15", "2.5.29.30"]) {
			const broken = await responder({ garbled: { id, critical: false } });
			expect(await reasonOf(await answer(broken)), id).toBe("signer");
		}
		const critical = await responder({ criticalUnknown: true });
		expect(await reasonOf(await answer(critical))).toBe("signer");
	});

	it("takes no delegated responder whose key usage is not one, rather than failing", async () => {
		const { intermediate, client, reasonOf, responder } = await setUp();
		const value = new asn1js.Sequence({ value: [new asn1js.Integer({ value: 1 })] }).toBER(false);
		const broken = await responder({ garbled: { id: "2.5.29.15", critical: false, value } });
		const der = await ocspOf({ cert: client, issuer: intermediate, by: broken, certs: [broken] });
		expect(await reasonOf(der)).toBe("signer");
	});

	it("uses nothing not signed by its signer's key strongly, nor anything malformed or failed", async () => {
		const { intermediate, client, reasonOf, responder } = await setUp();
		const base = { cert: client, issuer: intermediate };
		expect(await reasonOf(await ocspOf({ ...base, keys: await ecKeys() }))).toBe("signature");
		const delegated = await responder();
		const forged = await ocspOf({
			...base,
			by: delegated,
			certs: [delegated],
			keys: await ecKeys(),
		});
		expect(await reasonOf(forged)).toBe("signature");
		expect(await reasonOf(await ocspOf({ ...base, hash: "SHA-1" }))).toBe("signature algorithm");
		expect(await reasonOf(new Uint8Array([1, 2, 3]))).toBe("malformed");
		expect(await reasonOf(new Uint8Array([...(await ocspOf(base)), 0]))).toBe("malformed");
		expect(await reasonOf(await ocspOf({ ...base, responseStatus: 1 }))).toBe("status");
		expect(await reasonOf(await ocspOf({ ...base, responseStatus: 2 }))).toBe("busy");
		expect(await reasonOf(await ocspOf({ ...base, responseStatus: 3 }))).toBe("busy");
		expect(await reasonOf(await ocspOf({ ...base, responseStatus: 6 }))).toBe("status");
		const other = await issue({ cn: "other", by: intermediate });
		expect(await reasonOf(await ocspOf({ ...base, serialOf: other }))).toBe("not answered");
		expect(await reasonOf(await ocspOf({ ...base, criticalExtension: true }))).toBe("unsupported");
		expect(await reasonOf(await ocspOf({ ...base, garble: true }))).toBe("signature");
		expect(await reasonOf(await ocspOf({ ...base, responseType: "1.2.3.4" }))).toBe("malformed");
		const critical = new pkijs.Extension({
			extnID: "1.3.6.1.4.1.99999.4",
			critical: true,
			extnValue: new asn1js.Null().toBER(false),
		});
		const shaped = (shape: (single: pkijs.SingleResponse) => void) =>
			ocspOf({
				...base,
				shape: (basic) => shape(basic.tbsResponseData.responses[0] as pkijs.SingleResponse),
			});
		expect(await reasonOf(await shaped((single) => (single.singleExtensions = [critical])))).toBe(
			"unsupported",
		);
		const application = new asn1js.Primitive({ idBlock: { tagClass: 2, tagNumber: 0 } });
		expect(await reasonOf(await shaped((single) => (single.certStatus = application)))).toBe(
			"malformed",
		);
		const fourth = new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 3 } });
		expect(await reasonOf(await shaped((single) => (single.certStatus = fourth)))).toBe(
			"malformed",
		);
	});

	it("tells a responder that is down from an answer it cannot use, by kind", async () => {
		const { intermediate, client } = await setUp();
		for (const responseStatus of [2, 3]) {
			const der = await ocspOf({ cert: client, issuer: intermediate, responseStatus });
			const judged = await judgeOcsp(der, client.certificate, intermediate.certificate, asked());
			expect(judged).toEqual({ kind: "busy" });
		}
	});

	it("holds the answer to the nonce asked with, and to its update window", async () => {
		const { intermediate, client, reasonOf } = await setUp();
		const base = { cert: client, issuer: intermediate };
		expect(await reasonOf(await ocspOf({ ...base, nonce }), { nonce })).toBe("good");
		expect(await reasonOf(await ocspOf(base), { nonce })).toBe("nonce");
		expect(await reasonOf(await ocspOf({ ...base, nonce: new Uint8Array(16) }), { nonce })).toBe(
			"nonce",
		);
		expect(await reasonOf(await ocspOf({ ...base, nonce }))).toBe("good");
		expect(await reasonOf(await ocspOf({ ...base, nonce: nonce.slice(0, 8) }), { nonce })).toBe(
			"nonce",
		);
		const asInteger = await ocspOf({
			...base,
			shape: (basic) => {
				basic.tbsResponseData.responseExtensions = [
					new pkijs.Extension({
						extnID: "1.3.6.1.5.5.7.48.1.2",
						extnValue: new asn1js.Integer({ valueHex: nonce }).toBER(false),
					}),
				];
			},
		});
		expect(await reasonOf(asInteger, { nonce })).toBe("nonce");
		const now = Date.now();
		const window = async (thisUpdate: number, nextUpdate: number | null, at = now) =>
			reasonOf(await ocspOf({ ...base, thisUpdate, nextUpdate }), { now: at });
		expect(await window(now - 60_000, now + 60_000, now + 61_000)).toBe("stale");
		expect(await window(now - 60_000, now + 60_000, now + 59_000)).toBe("good");
		expect(await window(now - 600_000 - 2_000, null)).toBe("stale");
		expect(await window(now - 600_000 + 2_000, null)).toBe("good");
		expect(await window(now + 300_000 + 2_000, now + 3_600_000)).toBe("not yet");
		expect(await window(now + 300_000 - 2_000, now + 3_600_000)).toBe("good");
		const judged = await judgeOcsp(
			await ocspOf({ ...base, thisUpdate: now - 60_000, nextUpdate: null }),
			client.certificate,
			intermediate.certificate,
			asked({ now }),
		);
		expect(judged.kind === "good" && Math.abs(judged.until - (now - 60_000 + 600_000)) < 1000).toBe(
			true,
		);
	});
});

describe("asking an OCSP responder", () => {
	it("reads the http and https OCSP locations a certificate gives", async () => {
		const { intermediate } = await hierarchy();
		const cert = await issue({ cn: "client", by: intermediate, ocsp: "http://ocsp.example/" });
		expect(ocspUrlsOf(cert.certificate)).toEqual(["http://ocsp.example/"]);
		const described = (accessMethod: string, type: 2 | 6, value: string) =>
			new pkijs.AccessDescription({
				accessMethod,
				accessLocation: new pkijs.GeneralName({ type, value }),
			});
		const others = await issue({
			cn: "client",
			by: intermediate,
			access: [
				described("1.3.6.1.5.5.7.48.2", 6, "http://issuers.example/"),
				described("1.3.6.1.5.5.7.48.1", 2, "http://named.example/"),
			],
		});
		expect(ocspUrlsOf(others.certificate)).toEqual([]);
		const ldap = await issue({ cn: "client", by: intermediate, ocsp: "ldap://ocsp.example/" });
		expect(ocspUrlsOf(ldap.certificate)).toEqual([]);
		expect(ocspUrlsOf(intermediate.certificate)).toEqual([]);
	});

	it("asks about the certificate by its issuer's name and key, with the nonce where one is given", async () => {
		const { intermediate, client } = await hierarchy();
		const read = async (bytes: Uint8Array) =>
			new pkijs.OCSPRequest({ schema: asn1js.fromBER(bytes).result }).tbsRequest;
		const expected = new pkijs.CertID();
		await expected.createForCertificate(client.certificate, {
			hashAlgorithm: "SHA-1",
			issuerCertificate: intermediate.certificate,
		});
		const withNonce = await read(
			await ocspRequestOf(client.certificate, intermediate.certificate, nonce),
		);
		expect(withNonce.requestList[0]?.reqCert.isEqual(expected)).toBe(true);
		const sent = withNonce.requestExtensions?.find((e) => e.extnID === "1.3.6.1.5.5.7.48.1.2");
		const value = asn1js.fromBER(
			sent?.extnValue.valueBlock.valueHexView ?? new Uint8Array(),
		).result;
		expect(new Uint8Array((value as asn1js.OctetString).valueBlock.valueHexView)).toEqual(nonce);
		const bare = await read(
			await ocspRequestOf(client.certificate, intermediate.certificate, undefined),
		);
		expect(bare.requestExtensions).toBeUndefined();
	});
});
