import type { webcrypto } from "node:crypto";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

const subtle = globalThis.crypto.subtle;

export type Keys = webcrypto.CryptoKeyPair;
export async function ecKeys(): Promise<Keys> {
	return (await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
		"sign",
		"verify",
	])) as Keys;
}
export async function rsaKeys(bits: number, name = "RSASSA-PKCS1-v1_5", hash = "SHA-256") {
	const publicExponent = new Uint8Array([1, 0, 1]);
	const algorithm = { name, modulusLength: bits, publicExponent, hash };
	return (await subtle.generateKey(algorithm, true, ["sign", "verify"])) as Keys;
}
/** RSA keys for PSS signatures over the given hash. */
export const pssKeys = (hash: "SHA-1" | "SHA-256") => rsaKeys(2048, "RSA-PSS", hash);

const name = (cn: string) => {
	const value = new asn1js.Utf8String({ value: cn });
	const typesAndValues = [new pkijs.AttributeTypeAndValue({ type: "2.5.4.3", value })];
	return new pkijs.RelativeDistinguishedNames({ typesAndValues });
};
/** A time as RFC 5280 writes it: UTCTime through 2049, GeneralizedTime from 2050. */
const timeOf = (ms: number) =>
	new pkijs.Time({ type: new Date(ms).getUTCFullYear() < 2050 ? 0 : 1, value: new Date(ms) });
/** An extension holding this ASN.1 value. */
const raw = (extnID: string, value: asn1js.AsnType | ArrayBuffer, critical = false) =>
	new pkijs.Extension({
		extnID,
		critical,
		extnValue: value instanceof ArrayBuffer ? value : value.toBER(false),
	});
const extension = (extnID: string, value: { toSchema(): asn1js.AsnType }, critical = false) =>
	raw(extnID, value.toSchema(), critical);
const unknownCritical = (extnID: string) => raw(extnID, new asn1js.Null(), true);

/** A distribution point by its full name. */
export const pointAt = (uri: string, more: Partial<pkijs.DistributionPointParameters> = {}) =>
	new pkijs.DistributionPoint({
		distributionPoint: [new pkijs.GeneralName({ type: 6, value: uri })],
		...more,
	});

export interface Issued {
	readonly cn: string;
	readonly keys: Keys;
	readonly der: Uint8Array;
	readonly certificate: pkijs.Certificate;
}

export interface Issuing {
	readonly cn: string;
	readonly keys?: Keys;
	/** Signed by this one; itself when left out. */
	readonly by?: Issued;
	readonly ca?: boolean;
	readonly pathLen?: number;
	readonly eku?: readonly string[] | undefined;
	readonly hash?: "SHA-1" | "SHA-256";
	readonly serial?: number;
	/** Epoch ms. */
	readonly notBefore?: number;
	readonly notAfter?: number;
	readonly crl?: string;
	readonly ocsp?: string;
	/** Access descriptions beyond `ocsp`, as they are written. */
	readonly access?: readonly pkijs.AccessDescription[];
	/** Names this issuer instead of the signer's name. */
	readonly issuerName?: string;
	readonly criticalUnknown?: boolean;
	/** The first byte of key usage; none when left out. */
	readonly keyUsage?: number;
	/** Marked as an OCSP responder that is not itself checked; with a value other than NULL when garbled. */
	readonly noCheck?: boolean | "garbled";
	/** An extension of this kind whose value does not parse as one. */
	readonly garbled?: {
		readonly id: string;
		readonly critical: boolean;
		/** The value's bytes; an INTEGER when left out. */
		readonly value?: ArrayBuffer;
	};
	/** Subject alternative names. */
	readonly san?: readonly pkijs.GeneralName[];
	/** Name constraints, as a CA states them; marked critical. */
	readonly permitted?: readonly pkijs.GeneralSubtree[];
	readonly excluded?: readonly pkijs.GeneralSubtree[];
	/** Distribution points beyond `crl`, as they are written. */
	readonly points?: readonly pkijs.DistributionPoint[];
	/** No basic constraints at all. */
	readonly bare?: boolean;
}

let serials = 100;
/** A certificate as a test authority issues it. */
export async function issue(spec: Issuing): Promise<Issued> {
	const keys = spec.keys ?? (await ecKeys());
	const c = new pkijs.Certificate();
	c.version = 2;
	c.serialNumber = new asn1js.Integer({ value: spec.serial ?? ++serials });
	c.subject = name(spec.cn);
	c.issuer = name(spec.issuerName ?? spec.by?.cn ?? spec.cn);
	c.notBefore = timeOf(spec.notBefore ?? Date.now() - 60_000);
	c.notAfter = timeOf(spec.notAfter ?? Date.now() + 86_400_000);
	const extensions: pkijs.Extension[] = [];
	if (!spec.bare) {
		const basic = new pkijs.BasicConstraints({
			cA: spec.ca ?? false,
			...(spec.pathLen === undefined ? {} : { pathLenConstraint: spec.pathLen }),
		});
		extensions.push(extension("2.5.29.19", basic, true));
	}
	if (spec.eku)
		extensions.push(extension("2.5.29.37", new pkijs.ExtKeyUsage({ keyPurposes: [...spec.eku] })));
	if (spec.keyUsage !== undefined) {
		const bits = new asn1js.BitString({ valueHex: new Uint8Array([spec.keyUsage]).buffer });
		extensions.push(extension("2.5.29.15", { toSchema: () => bits }, true));
	}
	const points = [...(spec.crl ? [pointAt(spec.crl)] : []), ...(spec.points ?? [])];
	if (points.length > 0) {
		extensions.push(
			extension("2.5.29.31", new pkijs.CRLDistributionPoints({ distributionPoints: points })),
		);
	}
	const access = [
		...(spec.ocsp
			? [
					new pkijs.AccessDescription({
						accessMethod: "1.3.6.1.5.5.7.48.1",
						accessLocation: new pkijs.GeneralName({ type: 6, value: spec.ocsp }),
					}),
				]
			: []),
		...(spec.access ?? []),
	];
	if (access.length > 0) {
		extensions.push(
			extension("1.3.6.1.5.5.7.1.1", new pkijs.InfoAccess({ accessDescriptions: access })),
		);
	}
	if (spec.noCheck) {
		const value = spec.noCheck === "garbled" ? new asn1js.Integer({ value: 1 }) : new asn1js.Null();
		extensions.push(raw("1.3.6.1.5.5.7.48.1.5", value));
	}
	if (spec.san) {
		extensions.push(extension("2.5.29.17", new pkijs.AltName({ altNames: [...spec.san] })));
	}
	if (spec.permitted || spec.excluded) {
		const constraints = new pkijs.NameConstraints({
			...(spec.permitted ? { permittedSubtrees: [...spec.permitted] } : {}),
			...(spec.excluded ? { excludedSubtrees: [...spec.excluded] } : {}),
		});
		extensions.push(extension("2.5.29.30", constraints, true));
	}
	if (spec.garbled) {
		const { id, critical, value } = spec.garbled;
		extensions.push(raw(id, value ?? new asn1js.Integer({ value: 5 }), critical));
	}
	if (spec.criticalUnknown) extensions.push(unknownCritical("1.3.6.1.4.1.99999.1"));
	c.extensions = extensions;
	await c.subjectPublicKeyInfo.importKey(keys.publicKey);
	await c.sign((spec.by?.keys ?? keys).privateKey, spec.hash ?? "SHA-256");
	const der = new Uint8Array(c.toSchema().toBER(false));
	return { cn: spec.cn, keys, der, certificate: c };
}

/** A root, an intermediate under it, and a client leaf under that. */
export async function hierarchy(leaf: Partial<Issuing> = {}) {
	const root = await issue({ cn: "root", ca: true });
	const intermediate = await issue({ cn: "intermediate", by: root, ca: true });
	const client = await issue({
		cn: "client",
		by: intermediate,
		eku: ["1.3.6.1.5.5.7.3.2"],
		...leaf,
	});
	return { root, intermediate, client };
}

export interface Revoking {
	readonly by: Issued;
	/** Signed with these instead of the issuer's own. */
	readonly keys?: Keys;
	/** Names this issuer instead. */
	readonly issuer?: string;
	readonly revoked?: readonly Issued[];
	readonly hash?: "SHA-1" | "SHA-256";
	/** Epoch ms. */
	readonly thisUpdate?: number;
	/** Epoch ms; none when null. */
	readonly nextUpdate?: number | null;
	readonly criticalExtension?: boolean;
	readonly criticalEntryExtension?: boolean;
	/** Further extensions of the CRL, and of each entry. */
	readonly extensions?: readonly pkijs.Extension[];
	readonly entryExtensions?: readonly pkijs.Extension[];
}

/** A CRL as a test authority signs it. */
export async function crlOf(spec: Revoking): Promise<Uint8Array> {
	const crl = new pkijs.CertificateRevocationList();
	crl.version = 1;
	crl.issuer = name(spec.issuer ?? spec.by.cn);
	crl.thisUpdate = timeOf(spec.thisUpdate ?? Date.now() - 60_000);
	if (spec.nextUpdate !== null) crl.nextUpdate = timeOf(spec.nextUpdate ?? Date.now() + 3_600_000);
	const unknown = () => unknownCritical("1.3.6.1.4.1.99999.2");
	const onEntry = [
		...(spec.criticalEntryExtension ? [unknown()] : []),
		...(spec.entryExtensions ?? []),
	];
	const revoked = (spec.revoked ?? []).map(
		(issued) =>
			new pkijs.RevokedCertificate({
				userCertificate: issued.certificate.serialNumber,
				revocationDate: timeOf(Date.now() - 60_000),
				...(onEntry.length > 0
					? { crlEntryExtensions: new pkijs.Extensions({ extensions: onEntry }) }
					: {}),
			}),
	);
	if (revoked.length > 0) crl.revokedCertificates = revoked;
	const onCrl = [...(spec.criticalExtension ? [unknown()] : []), ...(spec.extensions ?? [])];
	if (onCrl.length > 0) crl.crlExtensions = new pkijs.Extensions({ extensions: onCrl });
	await crl.sign((spec.keys ?? spec.by.keys).privateKey, spec.hash ?? "SHA-256");
	return new Uint8Array(crl.toSchema(true).toBER(false));
}

export interface Answering {
	/** The certificate asked about, and its issuer. */
	readonly cert: Issued;
	readonly issuer: Issued;
	/** Signs the answer; the issuer when left out. */
	readonly by?: Issued;
	/** Signed with these instead of the signer's own. */
	readonly keys?: Keys;
	readonly status?: "good" | "revoked" | "unknown";
	/** A revoked status's CRLReason. */
	readonly reason?: number;
	/** Epoch ms. */
	readonly thisUpdate?: number;
	/** Epoch ms; none when null. */
	readonly nextUpdate?: number | null;
	readonly nonce?: Uint8Array;
	/** The signer named by its key hash rather than its name. */
	readonly byKey?: boolean;
	readonly certs?: readonly Issued[];
	readonly hash?: "SHA-1" | "SHA-256";
	/** The answer is about this serial instead. */
	readonly serialOf?: Issued;
	readonly responseStatus?: number;
	readonly criticalExtension?: boolean;
	/** Changes the response before it is signed. */
	readonly shape?: (basic: pkijs.BasicOCSPResponse) => void | Promise<void>;
	/** Spoils the signature after signing. */
	readonly garble?: boolean;
	readonly responseType?: string;
}

/** An OCSP response as a test responder signs it. */
export async function ocspOf(spec: Answering): Promise<Uint8Array> {
	const signer = spec.by ?? spec.issuer;
	const basic = new pkijs.BasicOCSPResponse();
	if (spec.byKey) {
		const key = signer.certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView;
		const hashed = await subtle.digest("SHA-1", new Uint8Array(key));
		basic.tbsResponseData.responderID = new asn1js.OctetString({ valueHex: hashed });
	} else {
		basic.tbsResponseData.responderID = signer.certificate.subject;
	}
	basic.tbsResponseData.producedAt = new Date();
	const certID = new pkijs.CertID();
	await certID.createForCertificate((spec.serialOf ?? spec.cert).certificate, {
		hashAlgorithm: "SHA-1",
		issuerCertificate: spec.issuer.certificate,
	});
	const tag = { good: 0, revoked: 1, unknown: 2 }[spec.status ?? "good"];
	const single = new pkijs.SingleResponse({ certID });
	single.certStatus =
		tag === 1
			? new asn1js.Constructed({
					idBlock: { tagClass: 3, tagNumber: 1 },
					value: [
						new asn1js.GeneralizedTime({ valueDate: new Date(Date.now() - 60_000) }),
						...(spec.reason === undefined
							? []
							: [
									new asn1js.Constructed({
										idBlock: { tagClass: 3, tagNumber: 0 },
										value: [new asn1js.Enumerated({ value: spec.reason })],
									}),
								]),
					],
				})
			: new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: tag } });
	single.thisUpdate = new Date(spec.thisUpdate ?? Date.now() - 60_000);
	if (spec.nextUpdate !== null)
		single.nextUpdate = new Date(spec.nextUpdate ?? Date.now() + 3_600_000);
	basic.tbsResponseData.responses.push(single);
	const extensions: pkijs.Extension[] = [];
	if (spec.nonce) {
		extensions.push(raw("1.3.6.1.5.5.7.48.1.2", new asn1js.OctetString({ valueHex: spec.nonce })));
	}
	if (spec.criticalExtension) extensions.push(unknownCritical("1.3.6.1.4.1.99999.3"));
	if (extensions.length > 0) basic.tbsResponseData.responseExtensions = extensions;
	if (spec.certs) basic.certs = spec.certs.map((issued) => issued.certificate);
	await spec.shape?.(basic);
	await basic.sign((spec.keys ?? signer.keys).privateKey, spec.hash ?? "SHA-256");
	if (spec.garble)
		basic.signature = new asn1js.BitString({ valueHex: new Uint8Array([1, 2]).buffer });
	const response = new pkijs.OCSPResponse({
		responseStatus: new asn1js.Enumerated({ value: spec.responseStatus ?? 0 }),
		...(spec.responseStatus
			? {}
			: {
					responseBytes: new pkijs.ResponseBytes({
						responseType: spec.responseType ?? pkijs.id_PKIX_OCSP_Basic,
						response: new asn1js.OctetString({ valueHex: basic.toSchema().toBER(false) }),
					}),
				}),
	});
	return new Uint8Array(response.toSchema().toBER(false));
}

/** A certificate as PEM text. */
export const pemOf = (der: Uint8Array) =>
	`-----BEGIN CERTIFICATE-----\n${Buffer.from(der).toString("base64").replace(/.{64}/g, "$&\n")}\n-----END CERTIFICATE-----\n`;

/** A DNS name, or the subtree under one. */
export const dns = (value: string) => new pkijs.GeneralName({ type: 2, value });
/** An IP address (4 or 16 bytes), or a network as address and mask. */
export const ip = (...bytes: number[]) =>
	new pkijs.GeneralName({
		type: 7,
		value: new asn1js.OctetString({ valueHex: new Uint8Array(bytes).buffer }),
	});
export const subtree = (
	base: pkijs.GeneralName,
	more: Partial<pkijs.GeneralSubtreeParameters> = {},
) => new pkijs.GeneralSubtree({ base, ...more });
