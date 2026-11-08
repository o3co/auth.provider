import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { describe, expect, it } from "vitest";
import { signatureAlgorithms } from "../../signatures/signatures.ts";
import {
	crlOf,
	ecKeys,
	hierarchy,
	type Issued,
	issue,
	pointAt,
	type Revoking,
	restated,
	rsaKeys,
} from "../../testing.ts";
import { crlSays, distributionPointsOf, type Judged, verifyCrl } from "../crl.ts";

/** What the CRL says of `cert`, verified then judged, as one reading does. */
async function judgeCrl(
	der: Uint8Array,
	cert: pkijs.Certificate,
	issuer: pkijs.Certificate,
	now: number,
	skewMs: number,
	taken: Parameters<typeof verifyCrl>[4],
): Promise<Judged> {
	const verified = await verifyCrl(der, issuer, now, skewMs, taken);
	return verified.kind === "unusable" ? verified : crlSays(verified.crl, cert, issuer, now);
}
/** The usable URLs of a certificate's distribution points; none where it has none, or they are unreadable. */
const crlUrlsOf = (cert: pkijs.Certificate) => {
	const points = distributionPointsOf(cert);
	return points.kind === "points" ? points.urls : [];
};

const skewMs = 300_000;

/** What the CRL says of `cert`: its reason when unusable, else its kind. */
async function said(der: Uint8Array, cert: Issued, issuer: Issued, at = Date.now()) {
	const judged = await judgeCrl(
		der,
		cert.certificate,
		issuer.certificate,
		at,
		skewMs,
		signatureAlgorithms,
	);
	return judged.kind === "unusable" ? judged.reason : judged.kind;
}

describe("judging a CRL", () => {
	it("tells a listed certificate revoked and another good, until the next update", async () => {
		const { intermediate, client } = await hierarchy();
		const other = await issue({ cn: "other", by: intermediate });
		const next = Date.now() + 3_600_000;
		const judge = async (der: Uint8Array) =>
			judgeCrl(
				der,
				client.certificate,
				intermediate.certificate,
				Date.now(),
				skewMs,
				signatureAlgorithms,
			);
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
			signatureAlgorithms,
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
			await judgeCrl(
				der,
				client.certificate,
				intermediate.certificate,
				Date.now(),
				skewMs,
				signatureAlgorithms,
			),
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

	it("uses nothing from a CRL signed by an algorithm its policy leaves out", async () => {
		const { intermediate, client } = await hierarchy();
		const der = await crlOf({ by: intermediate, hash: "SHA-384" });
		const judge = (taken: Parameters<typeof judgeCrl>[5]) =>
			judgeCrl(der, client.certificate, intermediate.certificate, Date.now(), skewMs, taken);
		expect(await judge(["ecdsa-sha256"])).toEqual({
			kind: "unusable",
			reason: "signature algorithm",
		});
		expect((await judge(["ecdsa-sha384"])).kind).toBe("good");
	});

	it("uses nothing from a CRL stating another algorithm than it was signed by", async () => {
		const root = await issue({ cn: "root", ca: true });
		const intermediate = await issue({ cn: "int", by: root, ca: true, keys: await rsaKeys(2048) });
		const client = await issue({ cn: "client", by: intermediate });
		const der = await crlOf({ by: intermediate });
		expect(await said(der, client, intermediate)).toBe("good");
		const asEcdsa = restated("crl", der, "1.2.840.10045.4.3.2");
		expect(await said(asEcdsa, client, intermediate)).toBe("signature algorithm");
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
				await judgeCrl(
					der,
					client.certificate,
					intermediate.certificate,
					Date.now(),
					skewMs,
					signatureAlgorithms,
				),
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

describe("a verified CRL, apart from the certificate it is asked of", () => {
	const numbered = (value: bigint) => {
		const bytes = Buffer.from(
			value
				.toString(16)
				.padStart(2, "0")
				.replace(/^(.(..)*)$/, "0$1"),
			"hex",
		);
		return new pkijs.Extension({
			extnID: "2.5.29.20",
			extnValue: new asn1js.Integer({ valueHex: new Uint8Array(bytes).buffer }).toBER(false),
		});
	};

	it("reads its number whole, past 2^64, and none where it has none", async () => {
		const { intermediate } = await hierarchy();
		const big = 2n ** 70n + 5n;
		const der = await crlOf({ by: intermediate, extensions: [numbered(big)] });
		const verified = await verifyCrl(
			der,
			intermediate.certificate,
			Date.now(),
			skewMs,
			signatureAlgorithms,
		);
		expect(verified.kind === "verified" && verified.crl.number).toBe(big);
		const bare = await verifyCrl(
			await crlOf({ by: intermediate }),
			intermediate.certificate,
			Date.now(),
			skewMs,
			signatureAlgorithms,
		);
		expect(bare.kind === "verified" && "number" in bare.crl).toBe(false);
	});

	it("asks the issuer again at every judgment: another of the same name and key, unable to sign CRLs or out of date, is unusable", async () => {
		const { root, intermediate, client } = await hierarchy();
		const verified = await verifyCrl(
			await crlOf({ by: intermediate }),
			intermediate.certificate,
			Date.now(),
			skewMs,
			signatureAlgorithms,
		);
		if (verified.kind !== "verified") throw new Error(verified.reason);
		// The same name and key, as a cross-sign would be: one without cRLSign, one expired.
		const same = { cn: "intermediate", by: root, ca: true, keys: intermediate.keys };
		const noCrlSign = await issue({ ...same, keyUsage: 0x04 });
		expect(crlSays(verified.crl, client.certificate, noCrlSign.certificate, Date.now())).toEqual({
			kind: "unusable",
			reason: "issuer cannot sign crls",
		});
		const expired = await issue({ ...same, notAfter: Date.now() - 1000 });
		expect(crlSays(verified.crl, client.certificate, expired.certificate, Date.now())).toEqual({
			kind: "unusable",
			reason: "issuer out of date",
		});
	});

	it("takes a CRL whose number is not a non-negative INTEGER as malformed", async () => {
		const { intermediate } = await hierarchy();
		const numbered = (value: asn1js.BaseBlock) =>
			new pkijs.Extension({ extnID: "2.5.29.20", extnValue: value.toBER(false) });
		for (const value of [
			new asn1js.Utf8String({ value: "7" }),
			new asn1js.Integer({ value: -1 }),
		]) {
			const der = await crlOf({ by: intermediate, extensions: [numbered(value)] });
			const verified = await verifyCrl(
				der,
				intermediate.certificate,
				Date.now(),
				skewMs,
				signatureAlgorithms,
			);
			expect(verified).toEqual({ kind: "unusable", reason: "malformed" });
		}
	});

	it("tells, asked later, a CRL past its next update stale, and one of another issuer's certificate unusable", async () => {
		const { root, intermediate, client } = await hierarchy();
		const next = Date.now() + 60_000;
		const verified = await verifyCrl(
			await crlOf({ by: intermediate, revoked: [client], nextUpdate: next }),
			intermediate.certificate,
			Date.now(),
			skewMs,
			signatureAlgorithms,
		);
		if (verified.kind !== "verified") throw new Error(verified.reason);
		const now = crlSays(verified.crl, client.certificate, intermediate.certificate, Date.now());
		expect(now).toMatchObject({ kind: "revoked", held: false });
		expect(crlSays(verified.crl, client.certificate, intermediate.certificate, next + 1)).toEqual({
			kind: "unusable",
			reason: "stale",
		});
		expect(crlSays(verified.crl, intermediate.certificate, root.certificate, Date.now())).toEqual({
			kind: "unusable",
			reason: "issuer",
		});
	});
});

describe("a certificate's distribution points", () => {
	it("tells none, an unreadable extension and the points apart, counting the points it cannot use", async () => {
		const { intermediate } = await hierarchy();
		expect(distributionPointsOf(intermediate.certificate)).toEqual({ kind: "none" });
		const garbled = await issue({
			cn: "client",
			by: intermediate,
			garbled: { id: "2.5.29.31", critical: false },
		});
		expect(distributionPointsOf(garbled.certificate)).toEqual({ kind: "malformed" });
		const mixed = await issue({
			cn: "client",
			by: intermediate,
			crl: "http://ca.example/crl",
			points: [
				pointAt("ldap://ca.example/crl"),
				pointAt("http://ca.example/other", {
					cRLIssuer: [new pkijs.GeneralName({ type: 6, value: "http://other.example" })],
				}),
			],
		});
		expect(distributionPointsOf(mixed.certificate)).toEqual({
			kind: "points",
			urls: ["http://ca.example/crl"],
			unusable: 2,
		});
	});
});
