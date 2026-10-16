import { createHash, type webcrypto } from "node:crypto";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

const subtle = globalThis.crypto.subtle;

const name = (cn: string) =>
	new pkijs.RelativeDistinguishedNames({
		typesAndValues: [
			new pkijs.AttributeTypeAndValue({
				type: "2.5.4.3",
				value: new asn1js.Utf8String({ value: cn }),
			}),
		],
	});
const extension = (extnID: string, value: asn1js.AsnType, critical = false) =>
	new pkijs.Extension({ extnID, critical, extnValue: value.toBER(false) });

export interface Issued {
	readonly cn: string;
	readonly keys: webcrypto.CryptoKeyPair;
	readonly der: Uint8Array;
	readonly certificate: pkijs.Certificate;
}

let serials = 1000;
/** A certificate as a test authority issues it: a CA, or a client certificate with its CRL's location. */
export async function issue(spec: {
	readonly cn: string;
	readonly by?: Issued;
	readonly ca?: boolean;
	readonly crl?: string;
	readonly ocsp?: string;
}): Promise<Issued> {
	const keys = (await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
		"sign",
		"verify",
	])) as webcrypto.CryptoKeyPair;
	const c = new pkijs.Certificate();
	c.version = 2;
	c.serialNumber = new asn1js.Integer({ value: ++serials });
	c.subject = name(spec.cn);
	c.issuer = name(spec.by?.cn ?? spec.cn);
	c.notBefore.value = new Date(Date.now() - 60_000);
	c.notAfter.value = new Date(Date.now() + 86_400_000);
	const basic = new pkijs.BasicConstraints({ cA: spec.ca ?? false });
	c.extensions = [extension("2.5.29.19", basic.toSchema(), true)];
	if (!spec.ca) {
		const usage = new pkijs.ExtKeyUsage({ keyPurposes: ["1.3.6.1.5.5.7.3.2"] });
		c.extensions.push(extension("2.5.29.37", usage.toSchema()));
	}
	if (spec.crl) {
		const point = new pkijs.DistributionPoint({
			distributionPoint: [new pkijs.GeneralName({ type: 6, value: spec.crl })],
		});
		const points = new pkijs.CRLDistributionPoints({ distributionPoints: [point] });
		c.extensions.push(extension("2.5.29.31", points.toSchema()));
	}
	if (spec.ocsp) {
		const access = new pkijs.AccessDescription({
			accessMethod: "1.3.6.1.5.5.7.48.1",
			accessLocation: new pkijs.GeneralName({ type: 6, value: spec.ocsp }),
		});
		const info = new pkijs.InfoAccess({ accessDescriptions: [access] });
		c.extensions.push(extension("1.3.6.1.5.5.7.1.1", info.toSchema()));
	}
	await c.subjectPublicKeyInfo.importKey(keys.publicKey);
	await c.sign((spec.by?.keys ?? keys).privateKey, "SHA-256");
	return { cn: spec.cn, keys, der: new Uint8Array(c.toSchema().toBER(false)), certificate: c };
}

/** The issuer's CRL, listing these certificates. */
export async function crlOf(by: Issued, revoked: readonly Issued[] = []): Promise<Uint8Array> {
	const crl = new pkijs.CertificateRevocationList();
	crl.version = 1;
	crl.issuer = name(by.cn);
	crl.thisUpdate = new pkijs.Time({ type: 0, value: new Date(Date.now() - 60_000) });
	crl.nextUpdate = new pkijs.Time({ type: 0, value: new Date(Date.now() + 3_600_000) });
	if (revoked.length > 0) {
		crl.revokedCertificates = revoked.map(
			(issued) =>
				new pkijs.RevokedCertificate({
					userCertificate: issued.certificate.serialNumber,
					revocationDate: new pkijs.Time({ type: 0, value: new Date(Date.now() - 60_000) }),
				}),
		);
	}
	await crl.sign(by.keys.privateKey, "SHA-256");
	return new Uint8Array(crl.toSchema(true).toBER(false));
}

export const pemOf = (der: Uint8Array) =>
	`-----BEGIN CERTIFICATE-----\n${Buffer.from(der).toString("base64").replace(/.{64}/g, "$&\n")}\n-----END CERTIFICATE-----\n`;

/** The certificate's thumbprint, as a bound token's `cnf` carries it. */
export const thumbprintOf = (der: Uint8Array) =>
	createHash("sha256").update(der).digest("base64url");

const nonceId = "1.3.6.1.5.5.7.48.1.2";

/**
 * The issuer's answer to an OCSP request, about the certificate the request names, with the
 * request's nonce carried back unless told to leave it out.
 */
export async function ocspAnswer(
	request: Uint8Array,
	by: Issued,
	status: "good" | "revoked" | "unknown",
	carryNonce = true,
): Promise<Uint8Array> {
	const asked = new pkijs.OCSPRequest({ schema: asn1js.fromBER(request).result });
	const certID = asked.tbsRequest.requestList[0]?.reqCert;
	if (!certID) throw new Error("the request names no certificate");
	const basic = new pkijs.BasicOCSPResponse();
	basic.tbsResponseData.responderID = by.certificate.subject;
	basic.tbsResponseData.producedAt = new Date();
	const single = new pkijs.SingleResponse({ certID });
	single.certStatus =
		status === "revoked"
			? new asn1js.Constructed({
					idBlock: { tagClass: 3, tagNumber: 1 },
					value: [new asn1js.GeneralizedTime({ valueDate: new Date(Date.now() - 60_000) })],
				})
			: new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: status === "good" ? 0 : 2 } });
	single.thisUpdate = new Date(Date.now() - 60_000);
	single.nextUpdate = new Date(Date.now() + 3_600_000);
	basic.tbsResponseData.responses.push(single);
	const nonce = asked.tbsRequest.requestExtensions?.find((e) => e.extnID === nonceId);
	if (nonce && carryNonce) basic.tbsResponseData.responseExtensions = [nonce];
	await basic.sign(by.keys.privateKey, "SHA-256");
	const response = new pkijs.OCSPResponse({
		responseStatus: new asn1js.Enumerated({ value: 0 }),
		responseBytes: new pkijs.ResponseBytes({
			responseType: pkijs.id_PKIX_OCSP_Basic,
			response: new asn1js.OctetString({ valueHex: basic.toSchema().toBER(false) }),
		}),
	});
	return new Uint8Array(response.toSchema().toBER(false));
}
