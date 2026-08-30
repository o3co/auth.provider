/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * In-process PKI factory for the `full-pki` tests.
 *
 * **Why not committed PEM fixtures.** The narrow-mode tests use committed
 * fixtures (`__tests__/fixtures/`) and those stay exactly as they are — five
 * certificate shapes is a set you can name in a README. Full RFC 5280 path
 * validation is not: these tests need name constraints, path-length
 * constraints, `keyCertSign`, unrecognised critical extensions, algorithm
 * policy, CRL distribution points, and CRLs that are fresh, stale, forged,
 * and revoking — in combinations, at several chain depths. Committing that
 * as PEM would be dozens of opaque files, and every CRL carries a
 * `nextUpdate` that turns into a test that starts failing on a calendar date
 * nobody chose.
 *
 * Minting in-process makes each test say what shape it needs, and lets the
 * clock be an argument instead of a countdown. It costs no new dependency:
 * `pkijs` is already the path-validation engine under test.
 *
 * Everything here is ECDSA P-256 unless a test asks otherwise, because RSA
 * key generation is slow enough to notice across a suite this size.
 */

import { X509Certificate } from "node:crypto";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

/** OIDs used by the shapes these tests mint. */
const OID = {
	commonName: "2.5.4.3",
	basicConstraints: "2.5.29.19",
	keyUsage: "2.5.29.15",
	extKeyUsage: "2.5.29.37",
	crlDistributionPoints: "2.5.29.31",
	nameConstraints: "2.5.29.30",
	authorityInfoAccess: "1.3.6.1.5.5.7.1.1",
	ocsp: "1.3.6.1.5.5.7.48.1",
	clientAuth: "1.3.6.1.5.5.7.3.2",
	serverAuth: "1.3.6.1.5.5.7.3.1",
	subjectAltName: "2.5.29.17",
} as const;

/** `KeyUsage` bit positions, MSB-first within the first octet (RFC 5280 §4.2.1.3). */
export const KEY_USAGE = {
	digitalSignature: 0b1000_0000,
	keyEncipherment: 0b0010_0000,
	keyCertSign: 0b0000_0100,
	cRLSign: 0b0000_0010,
} as const;

const engine = (): pkijs.ICryptoEngine => pkijs.getCrypto(true);

export type KeyAlgorithm = "ec-p256" | "rsa-2048" | "rsa-1024";

const generateKeys = async (algorithm: KeyAlgorithm): Promise<CryptoKeyPair> => {
	const crypto = engine();
	if (algorithm === "ec-p256") {
		return (await crypto.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
			"sign",
			"verify",
		])) as CryptoKeyPair;
	}
	const modulusLength = algorithm === "rsa-2048" ? 2048 : 1024;
	return (await crypto.generateKey(
		{
			name: "RSASSA-PKCS1-v1_5",
			modulusLength,
			publicExponent: new Uint8Array([1, 0, 1]),
			hash: "SHA-256",
		},
		true,
		["sign", "verify"],
	)) as CryptoKeyPair;
};

const setCommonName = (name: pkijs.RelativeDistinguishedNames, cn: string): void => {
	name.typesAndValues.push(
		new pkijs.AttributeTypeAndValue({
			type: OID.commonName,
			value: new asn1js.Utf8String({ value: cn }),
		}),
	);
};

// ---------------------------------------------------------------------------
// Extension builders
// ---------------------------------------------------------------------------

export const basicConstraints = (ca: boolean, pathLenConstraint?: number): pkijs.Extension =>
	new pkijs.Extension({
		extnID: OID.basicConstraints,
		critical: true,
		extnValue: new pkijs.BasicConstraints({
			cA: ca,
			...(pathLenConstraint === undefined ? {} : { pathLenConstraint }),
		})
			.toSchema()
			.toBER(false),
	});

export const keyUsage = (bits: number): pkijs.Extension => {
	const octet = new Uint8Array([bits]);
	return new pkijs.Extension({
		extnID: OID.keyUsage,
		critical: true,
		extnValue: new asn1js.BitString({
			valueHex: octet.buffer as ArrayBuffer,
			unusedBits: 0,
		}).toBER(false),
	});
};

export const clientAuthEku = (): pkijs.Extension =>
	new pkijs.Extension({
		extnID: OID.extKeyUsage,
		critical: false,
		extnValue: new pkijs.ExtKeyUsage({ keyPurposes: [OID.clientAuth] }).toSchema().toBER(false),
	});

/** `extendedKeyUsage` naming only `serverAuth` — a server cert offered as a client credential. */
export const serverAuthEku = (): pkijs.Extension =>
	new pkijs.Extension({
		extnID: OID.extKeyUsage,
		critical: false,
		extnValue: new pkijs.ExtKeyUsage({ keyPurposes: [OID.serverAuth] }).toSchema().toBER(false),
	});

/** `extendedKeyUsage` marked CRITICAL — meaningful on a leaf, EKU chaining on a CA. */
export const criticalClientAuthEku = (): pkijs.Extension =>
	new pkijs.Extension({
		extnID: OID.extKeyUsage,
		critical: true,
		extnValue: new pkijs.ExtKeyUsage({ keyPurposes: [OID.clientAuth] }).toSchema().toBER(false),
	});

export const crlDistributionPoints = (urls: readonly string[]): pkijs.Extension =>
	new pkijs.Extension({
		extnID: OID.crlDistributionPoints,
		critical: false,
		extnValue: new pkijs.CRLDistributionPoints({
			distributionPoints: urls.map(
				(url) =>
					new pkijs.DistributionPoint({
						distributionPoint: [new pkijs.GeneralName({ type: 6, value: url })],
					}),
			),
		})
			.toSchema()
			.toBER(false),
	});

export const ocspAia = (url: string): pkijs.Extension =>
	new pkijs.Extension({
		extnID: OID.authorityInfoAccess,
		critical: false,
		extnValue: new pkijs.InfoAccess({
			accessDescriptions: [
				new pkijs.AccessDescription({
					accessMethod: OID.ocsp,
					accessLocation: new pkijs.GeneralName({ type: 6, value: url }),
				}),
			],
		})
			.toSchema()
			.toBER(false),
	});

/** A `subjectAltName` extension carrying dNSName entries — what name constraints match against. */
export const dnsSan = (names: readonly string[]): pkijs.Extension =>
	new pkijs.Extension({
		extnID: "2.5.29.17",
		critical: false,
		extnValue: new pkijs.GeneralNames({
			names: names.map((dns) => new pkijs.GeneralName({ type: 2, value: dns })),
		})
			.toSchema()
			.toBER(false),
	});

/** A `nameConstraints` extension over DNS subtrees — CRITICAL, per RFC 5280 §4.2.1.10. */
export const nameConstraints = (opts: {
	readonly permittedDns?: readonly string[];
	readonly excludedDns?: readonly string[];
}): pkijs.Extension => {
	const subtree = (dns: string) =>
		new pkijs.GeneralSubtree({ base: new pkijs.GeneralName({ type: 2, value: dns }) });
	return new pkijs.Extension({
		extnID: OID.nameConstraints,
		critical: true,
		extnValue: new pkijs.NameConstraints({
			...(opts.permittedDns ? { permittedSubtrees: opts.permittedDns.map(subtree) } : {}),
			...(opts.excludedDns ? { excludedSubtrees: opts.excludedDns.map(subtree) } : {}),
		})
			.toSchema()
			.toBER(false),
	});
};

/**
 * An extension whose OID nothing recognises, marked CRITICAL.
 *
 * RFC 5280 §6.1.2: a validator that does not recognise a critical extension
 * MUST reject the certificate. The OID is from the private-use arc so it can
 * never collide with something a future library version learns to parse.
 */
export const unknownCriticalExtension = (): pkijs.Extension =>
	new pkijs.Extension({
		extnID: "1.3.6.1.4.1.99999.1.1",
		critical: true,
		extnValue: new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3]).buffer }).toBER(false),
	});

// ---------------------------------------------------------------------------
// Minting
// ---------------------------------------------------------------------------

export interface Minted {
	readonly cn: string;
	readonly serial: number;
	readonly keys: CryptoKeyPair;
	readonly cert: pkijs.Certificate;
	readonly pem: string;
	readonly x509: X509Certificate;
	readonly der: Uint8Array;
}

export interface MintOptions {
	readonly cn: string;
	readonly serial: number;
	/** Omit for a self-signed certificate. */
	readonly issuer?: Minted;
	readonly notBefore?: Date;
	readonly notAfter?: Date;
	readonly extensions?: readonly pkijs.Extension[];
	readonly algorithm?: KeyAlgorithm;
	/** Digest for the signature. `"SHA-1"` exercises the algorithm allowlist. */
	readonly hash?: "SHA-256" | "SHA-384" | "SHA-1";
	/** Reuse an existing key pair (for same-key, different-shape fixtures). */
	readonly keys?: CryptoKeyPair;
}

const DEFAULT_NOT_BEFORE = new Date("2026-01-01T00:00:00Z");
const DEFAULT_NOT_AFTER = new Date("2036-01-01T00:00:00Z");

const toPem = (der: Uint8Array): string => {
	const b64 = Buffer.from(der).toString("base64");
	const lines = b64.match(/.{1,64}/g) ?? [];
	return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
};

export const mint = async (options: MintOptions): Promise<Minted> => {
	const crypto = engine();
	const keys = options.keys ?? (await generateKeys(options.algorithm ?? "ec-p256"));
	const cert = new pkijs.Certificate();
	cert.version = 2;
	cert.serialNumber = new asn1js.Integer({ value: options.serial });
	setCommonName(cert.subject, options.cn);
	setCommonName(cert.issuer, options.issuer?.cn ?? options.cn);
	cert.notBefore.value = options.notBefore ?? DEFAULT_NOT_BEFORE;
	cert.notAfter.value = options.notAfter ?? DEFAULT_NOT_AFTER;
	cert.extensions = [...(options.extensions ?? [])];
	await cert.subjectPublicKeyInfo.importKey(keys.publicKey, crypto);
	const signingKey = options.issuer?.keys.privateKey ?? keys.privateKey;
	await cert.sign(signingKey, options.hash ?? "SHA-256", crypto);
	const der = new Uint8Array(cert.toSchema(true).toBER(false));
	const pem = toPem(der);
	return {
		cn: options.cn,
		serial: options.serial,
		keys,
		cert,
		pem,
		x509: new X509Certificate(pem),
		der,
	};
};

/** A self-signed CA with `keyCertSign` + `cRLSign`, the shape a trust anchor has. */
export const mintCa = (
	cn: string,
	serial: number,
	extra: Partial<MintOptions> = {},
): Promise<Minted> =>
	mint({
		cn,
		serial,
		extensions: [basicConstraints(true), keyUsage(KEY_USAGE.keyCertSign | KEY_USAGE.cRLSign)],
		...extra,
	});

/** A CA signed by `issuer`. */
export const mintIntermediate = (
	cn: string,
	serial: number,
	issuer: Minted,
	extra: Partial<MintOptions> = {},
): Promise<Minted> =>
	mint({
		cn,
		serial,
		issuer,
		extensions: [basicConstraints(true), keyUsage(KEY_USAGE.keyCertSign | KEY_USAGE.cRLSign)],
		...extra,
	});

/** An end-entity client certificate. */
export const mintLeaf = (
	cn: string,
	serial: number,
	issuer: Minted,
	extra: Partial<MintOptions> = {},
): Promise<Minted> =>
	mint({
		cn,
		serial,
		issuer,
		extensions: [basicConstraints(false), keyUsage(KEY_USAGE.digitalSignature), clientAuthEku()],
		...extra,
	});

// ---------------------------------------------------------------------------
// CRLs
// ---------------------------------------------------------------------------

export interface MintCrlOptions {
	readonly issuer: Minted;
	/** Certificates to list as revoked. */
	readonly revoked?: readonly Minted[];
	readonly thisUpdate?: Date;
	/** Omit for a CRL with no `nextUpdate` at all. */
	readonly nextUpdate?: Date | null;
	/** Sign with this key instead of the issuer's — for the forged-CRL test. */
	readonly signingKeys?: CryptoKeyPair;
}

/** Returns the DER bytes of a signed CRL. */
export const mintCrl = async (options: MintCrlOptions): Promise<Uint8Array> => {
	const crypto = engine();
	const crl = new pkijs.CertificateRevocationList();
	crl.version = 1;
	setCommonName(crl.issuer, options.issuer.cn);
	crl.thisUpdate = new pkijs.Time({
		type: 0,
		value: options.thisUpdate ?? DEFAULT_NOT_BEFORE,
	});
	if (options.nextUpdate !== null) {
		crl.nextUpdate = new pkijs.Time({
			type: 0,
			value: options.nextUpdate ?? DEFAULT_NOT_AFTER,
		});
	}
	if (options.revoked && options.revoked.length > 0) {
		crl.revokedCertificates = options.revoked.map(
			(entry) =>
				new pkijs.RevokedCertificate({
					userCertificate: new asn1js.Integer({ value: entry.serial }),
					revocationDate: new pkijs.Time({
						type: 0,
						value: options.thisUpdate ?? DEFAULT_NOT_BEFORE,
					}),
				}),
		);
	}
	await crl.sign((options.signingKeys ?? options.issuer.keys).privateKey, "SHA-256", crypto);
	return new Uint8Array(crl.toSchema(true).toBER(false));
};
