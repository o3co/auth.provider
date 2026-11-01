import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { describe, expect, it } from "vitest";
import {
	crlOf,
	ecKeys,
	hierarchy,
	type Issued,
	issue,
	pointAt,
	type Revoking,
	rsaKeys,
} from "../../test/authority.ts";
import { crlUrlsOf, judgeCrl } from "../crl.ts";

const skewMs = 300_000;

/** What the CRL says of `cert`: its reason when unusable, else its kind. */
async function said(der: Uint8Array, cert: Issued, issuer: Issued, at = Date.now()) {
	const judged = await judgeCrl(der, cert.certificate, issuer.certificate, at, skewMs);
	return judged.kind === "unusable" ? judged.reason : judged.kind;
}

describe("judging a CRL", () => {
	it("tells a listed certificate revoked and another good, until the next update", async () => {
		const { intermediate, client } = await hierarchy();
		const other = await issue({ cn: "other", by: intermediate });
		const next = Date.now() + 3_600_000;
		const judge = async (der: Uint8Array) =>
			judgeCrl(der, client.certificate, intermediate.certificate, Date.now(), skewMs);
		expect(
			await judge(await crlOf({ by: intermediate, revoked: [client], nextUpdate: next })),
		).toEqual({ kind: "revoked", until: Math.floor(next / 1000) * 1000, held: false });
		expect(
			await judge(await crlOf({ by: intermediate, revoked: [other], nextUpdate: next })),
		).toEqual({
			kind: "good",
			until: Math.floor(next / 1000) * 1000,
		});
		expect((await judge(await crlOf({ by: intermediate }))).kind).toBe("good");
	});

	it("keeps its answer no longer than the issuer that signed it is in date", async () => {
		const root = await issue({ cn: "root", ca: true });
		const ends = Date.now() + 600_000;
		const intermediate = await issue({ cn: "intermediate", by: root, ca: true, notAfter: ends });
		const client = await issue({ cn: "client", by: intermediate });
		const der = await crlOf({ by: intermediate, nextUpdate: Date.now() + 3_600_000 });
		const judged = await judgeCrl(
			der,
			client.certificate,
			intermediate.certificate,
			Date.now(),
			skewMs,
		);
		expect(judged).toEqual({
			kind: "good",
			until: intermediate.certificate.notAfter.value.getTime(),
		});
	});

	it("reads a next update past 2049, which RFC 5280 writes as GeneralizedTime", async () => {
		const ends = Date.UTC(2070, 0, 1);
		const root = await issue({ cn: "root", ca: true, notAfter: ends });
		const intermediate = await issue({ cn: "intermediate", by: root, ca: true, notAfter: ends });
		const client = await issue({ cn: "client", by: intermediate });
		const next = Date.UTC(2055, 0, 1);
		const der = await crlOf({ by: intermediate, revoked: [client], nextUpdate: next });
		expect(
			await judgeCrl(der, client.certificate, intermediate.certificate, Date.now(), skewMs),
		).toEqual({ kind: "revoked", until: next, held: false });
	});

	it("takes a CRL holding a string that does not decode as malformed", async () => {
		const { intermediate, client } = await hierarchy();
		const garbled = new pkijs.CertificateRevocationList({
			schema: asn1js.fromBER(await crlOf({ by: intermediate, revoked: [client] })).result,
		});
		// A BMPString of an odd length, which asn1js 4 answers as a decode error, not a throw.
		const odd = new asn1js.BmpString({ valueHex: new Uint8Array([0, 0x41, 0]).buffer });
		garbled.issuer = new pkijs.RelativeDistinguishedNames({
			typesAndValues: [new pkijs.AttributeTypeAndValue({ type: "2.5.4.3", value: odd })],
		});
		const der = new Uint8Array(garbled.toSchema(true).toBER(false));
		expect(asn1js.fromBER(der).offset).toBe(-1);
		expect(await said(der, client, intermediate)).toBe("malformed");
	});

	it("uses nothing from a CRL that is not the issuer's, nor signed by it, nor signed strongly", async () => {
		const { intermediate, client } = await hierarchy();
		const reasonOf = (der: Uint8Array) => said(der, client, intermediate);
		const forged = await crlOf({ by: intermediate, keys: await ecKeys(), revoked: [client] });
		expect(await reasonOf(forged)).toBe("signature");
		const otherKind = await crlOf({
			by: intermediate,
			keys: await rsaKeys(2048),
			revoked: [client],
		});
		expect(await reasonOf(otherKind)).toBe("signature");
		const garbled = new pkijs.CertificateRevocationList({
			schema: asn1js.fromBER(await crlOf({ by: intermediate })).result,
		});
		garbled.signatureValue = new asn1js.BitString({ valueHex: new Uint8Array([1, 2, 3]).buffer });
		expect(await reasonOf(new Uint8Array(garbled.toSchema(true).toBER(false)))).toBe("signature");
		const named = await crlOf({ by: intermediate, issuer: "someone else", revoked: [client] });
		expect(await reasonOf(named)).toBe("issuer");
		expect(await reasonOf(await crlOf({ by: intermediate, hash: "SHA-1" }))).toBe(
			"signature algorithm",
		);
		expect(await reasonOf(new Uint8Array([1, 2, 3]))).toBe("malformed");
		const good = await crlOf({ by: intermediate });
		expect(await reasonOf(new Uint8Array([...good, 0]))).toBe("malformed");
	});

	it("takes a CRL only from an issuer whose key usage, where it has one, signs CRLs", async () => {
		const { root } = await hierarchy();
		const reasonOf = async (keyUsage: number) => {
			const issuer = await issue({ cn: "intermediate", by: root, ca: true, keyUsage });
			const client = await issue({ cn: "client", by: issuer });
			return said(await crlOf({ by: issuer }), client, issuer);
		};
		expect(await reasonOf(0x04)).toBe("issuer cannot sign crls");
		expect(await reasonOf(0x06)).toBe("good");
	});

	it("uses a CRL only between its this update, within the allowance, and its next update", async () => {
		const { intermediate, client } = await hierarchy();
		const now = Date.now();
		const reasonOf = async (thisUpdate: number, nextUpdate: number | null, at = now) => {
			const der = await crlOf({ by: intermediate, thisUpdate, nextUpdate });
			return said(der, client, intermediate, at);
		};
		expect(await reasonOf(now - 60_000, null)).toBe("stale");
		expect(await reasonOf(now - 60_000, now + 60_000, now + 61_000)).toBe("stale");
		expect(await reasonOf(now - 60_000, now + 60_000, now + 59_000)).toBe("good");
		expect(await reasonOf(now + skewMs + 2_000, now + 3_600_000)).toBe("not yet");
		expect(await reasonOf(now + skewMs - 2_000, now + 3_600_000)).toBe("good");
	});

	it("leaves to no other source a CRL with a critical extension it does not handle", async () => {
		const { intermediate, client } = await hierarchy();
		for (const der of [
			await crlOf({ by: intermediate, criticalExtension: true }),
			await crlOf({ by: intermediate, revoked: [client], criticalEntryExtension: true }),
		]) {
			expect(
				await judgeCrl(der, client.certificate, intermediate.certificate, Date.now(), skewMs),
			).toEqual({ kind: "unusable", reason: "unsupported" });
		}
	});

	it("leaves to no other source a delta or scoped CRL, or an indirect entry, critical or not", async () => {
		const { intermediate, client } = await hierarchy();
		const other = await issue({ cn: "other", by: intermediate });
		const marked = (extnID: string, value: asn1js.AsnType) =>
			new pkijs.Extension({ extnID, critical: false, extnValue: value.toBER(false) });
		const elsewhere = new pkijs.GeneralNames({
			names: [new pkijs.GeneralName({ type: 2, value: "other.example" })],
		});
		const reasonOf = async (spec: Partial<Revoking>) =>
			said(await crlOf({ by: intermediate, revoked: [other], ...spec }), client, intermediate);
		const delta = marked("2.5.29.27", new asn1js.Integer({ value: 1 }));
		const scope = new pkijs.IssuingDistributionPoint({ onlyContainsUserCerts: true });
		const scoped = marked("2.5.29.28", scope.toSchema());
		const indirect = marked("2.5.29.29", elsewhere.toSchema());
		expect(await reasonOf({ extensions: [delta] })).toBe("unsupported");
		expect(await reasonOf({ extensions: [scoped] })).toBe("unsupported");
		expect(await reasonOf({ entryExtensions: [indirect] })).toBe("unsupported");
		// Pointing to a delta elsewhere leaves this CRL complete.
		const points = new pkijs.CRLDistributionPoints({
			distributionPoints: [pointAt("http://crl.example/delta.crl")],
		});
		expect(await reasonOf({ extensions: [marked("2.5.29.46", points.toSchema())] })).toBe("good");
	});
});

describe("where a certificate's CRL is", () => {
	it("reads the http and https full names of points that cover every reason and name no other issuer", async () => {
		const { intermediate } = await hierarchy();
		const cert = await issue({
			cn: "client",
			by: intermediate,
			crl: "http://crl.example/a.crl",
			points: [
				pointAt("https://crl.example/b.crl"),
				pointAt("ldap://crl.example/c"),
				new pkijs.DistributionPoint({
					distributionPoint: [new pkijs.GeneralName({ type: 2, value: "http://crl.example/n" })],
				}),
				pointAt("http://crl.example/d.crl", {
					reasons: new asn1js.BitString({ valueHex: new Uint8Array([0x40]).buffer }),
				}),
				pointAt("http://crl.example/e.crl", {
					cRLIssuer: [new pkijs.GeneralName({ type: 2, value: "other.example" })],
				}),
			],
		});
		expect(crlUrlsOf(cert.certificate)).toEqual([
			"http://crl.example/a.crl",
			"https://crl.example/b.crl",
		]);
		expect(crlUrlsOf(intermediate.certificate)).toEqual([]);
		const relative = new pkijs.DistributionPoint({
			distributionPoint: new pkijs.RelativeDistinguishedNames({
				typesAndValues: [
					new pkijs.AttributeTypeAndValue({
						type: "2.5.4.3",
						value: new asn1js.Utf8String({ value: "http://crl.example/r" }),
					}),
				],
			}),
		});
		const named = await issue({ cn: "client", by: intermediate, points: [relative] });
		expect(crlUrlsOf(named.certificate)).toEqual([]);
	});
});
