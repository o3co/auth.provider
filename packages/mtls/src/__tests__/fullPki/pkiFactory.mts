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
	deltaCRLIndicator: "2.5.29.27",
	issuingDistributionPoint: "2.5.29.28",
	certificateIssuer: "2.5.29.29",
	caIssuers: "1.3.6.1.5.5.7.48.2",
	ocspBasic: "1.3.6.1.5.5.7.48.1.1",
	ocspNonce: "1.3.6.1.5.5.7.48.1.2",
	ocspNoCheck: "1.3.6.1.5.5.7.48.1.5",
	ocspSigning: "1.3.6.1.5.5.7.3.9",
	tlsFeature: "1.3.6.1.5.5.7.1.24",
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

const uriName = (url: string): pkijs.GeneralName => new pkijs.GeneralName({ type: 6, value: url });

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

/**
 * A `cRLDistributionPoints` extension carrying exactly `points`, in order —
 * for a certificate that mixes point shapes (a plain point beside a
 * partitioned or indirect one, #469). The builders below produce the
 * individual points.
 */
export const distributionPointsExtension = (
	points: readonly pkijs.DistributionPoint[],
): pkijs.Extension =>
	new pkijs.Extension({
		extnID: OID.crlDistributionPoints,
		critical: false,
		extnValue: new pkijs.CRLDistributionPoints({ distributionPoints: [...points] })
			.toSchema()
			.toBER(false),
	});

/**
 * One plain distribution point: a string names it by a single URI, an array
 * by several — which RFC 5280 §4.2.1.13 defines as alternative ways to obtain
 * the *same* CRL. No `reasons`, so it covers every reason code.
 */
export const distributionPoint = (urls: string | readonly string[]): pkijs.DistributionPoint =>
	new pkijs.DistributionPoint({
		distributionPoint: (typeof urls === "string" ? [urls] : urls).map(uriName),
	});

/**
 * A distribution point carrying `reasons` — the CA partitions its revocation
 * information by reason code across several CRLs (RFC 5280 §4.2.1.13), so no
 * single one of them is the whole answer.
 */
export const reasonPartitionedDistributionPoint = (url: string): pkijs.DistributionPoint =>
	new pkijs.DistributionPoint({
		distributionPoint: [uriName(url)],
		// ReasonFlags with keyCompromise (bit 1) set.
		reasons: new asn1js.BitString({ valueHex: new Uint8Array([0x40]).buffer, unusedBits: 0 }),
	});

/**
 * A distribution point naming a `cRLIssuer` — the CRL there is signed by
 * someone other than the certificate's issuer (an indirect CRL).
 */
export const indirectDistributionPoint = (
	url: string,
	crlIssuerCn: string,
): pkijs.DistributionPoint => {
	const issuer = new pkijs.RelativeDistinguishedNames();
	setCommonName(issuer, crlIssuerCn);
	return new pkijs.DistributionPoint({
		distributionPoint: [uriName(url)],
		cRLIssuer: [new pkijs.GeneralName({ type: 4, value: issuer })],
	});
};

/**
 * A `cRLDistributionPoints` extension of plain points. Each entry is one
 * distribution point, named as `distributionPoint` takes it.
 */
export const crlDistributionPoints = (
	points: readonly (string | readonly string[])[],
): pkijs.Extension => distributionPointsExtension(points.map(distributionPoint));

/** A `cRLDistributionPoints` extension whose only point is reason-partitioned. */
export const reasonPartitionedCrlDistributionPoint = (url: string): pkijs.Extension =>
	distributionPointsExtension([reasonPartitionedDistributionPoint(url)]);

/** A `cRLDistributionPoints` extension whose only point names a `cRLIssuer`. */
export const indirectCrlDistributionPoint = (url: string, crlIssuerCn: string): pkijs.Extension =>
	distributionPointsExtension([indirectDistributionPoint(url, crlIssuerCn)]);

const aiaExtension = (descriptions: readonly pkijs.AccessDescription[]): pkijs.Extension =>
	new pkijs.Extension({
		extnID: OID.authorityInfoAccess,
		critical: false,
		extnValue: new pkijs.InfoAccess({ accessDescriptions: [...descriptions] })
			.toSchema()
			.toBER(false),
	});

/**
 * An `authorityInfoAccess` naming one or more `id-ad-ocsp` responders, in
 * the order given (RFC 5280 §4.2.2.1 — several entries are alternatives).
 */
export const ocspAia = (url: string | readonly string[]): pkijs.Extension =>
	aiaExtension(
		(typeof url === "string" ? [url] : url).map(
			(location) =>
				new pkijs.AccessDescription({ accessMethod: OID.ocsp, accessLocation: uriName(location) }),
		),
	);

/** An `authorityInfoAccess` naming only a `caIssuers` location — no responder at all. */
export const caIssuersAia = (url: string): pkijs.Extension =>
	aiaExtension([
		new pkijs.AccessDescription({ accessMethod: OID.caIssuers, accessLocation: uriName(url) }),
	]);

/** `extendedKeyUsage` naming `id-kp-OCSPSigning` — what a delegated responder must carry (RFC 6960 §4.2.2.2). */
export const ocspSigningEku = (): pkijs.Extension =>
	new pkijs.Extension({
		extnID: OID.extKeyUsage,
		critical: false,
		extnValue: new pkijs.ExtKeyUsage({ keyPurposes: [OID.ocspSigning] }).toSchema().toBER(false),
	});

/** `id-pkix-ocsp-nocheck` (RFC 6960 §4.2.2.2.1): trust the responder for its certificate's lifetime. */
export const ocspNoCheck = (): pkijs.Extension =>
	new pkijs.Extension({
		extnID: OID.ocspNoCheck,
		critical: false,
		extnValue: new asn1js.Null().toBER(false),
	});

/**
 * The TLS feature extension (RFC 7633). `features` are TLS extension type
 * numbers; `[5]` (`status_request`) is OCSP must-staple.
 */
export const tlsFeature = (features: readonly number[], critical = false): pkijs.Extension =>
	new pkijs.Extension({
		extnID: OID.tlsFeature,
		critical,
		extnValue: new asn1js.Sequence({
			value: features.map((feature) => new asn1js.Integer({ value: feature })),
		}).toBER(false),
	});

export const mustStaple = (critical = false): pkijs.Extension => tlsFeature([5], critical);

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
 * A CRITICAL `keyUsage` that parses but carries no bits.
 *
 * RFC 5280 §6.1.2 covers an unrecognised critical extension **or** "a
 * critical extension that contains information that it cannot process". This
 * is the second half in its subtler form: everything parses, and the
 * restriction simply reads as empty — which is indistinguishable from
 * "unconstrained" unless the absent-vs-unreadable distinction is made
 * explicitly.
 */
export const emptyCriticalKeyUsage = (): pkijs.Extension =>
	new pkijs.Extension({
		extnID: OID.keyUsage,
		critical: true,
		// Well-formed DER, zero content octets. `parsedValue` is populated, so
		// the "did it parse" check passes — and the bit string then yields no
		// bits, which reads as "no restrictions" unless something says
		// otherwise.
		extnValue: new asn1js.BitString({
			valueHex: new ArrayBuffer(0),
			unusedBits: 0,
		}).toBER(false),
	});

/**
 * A CRITICAL `keyUsage` whose value is not valid DER at all, so pkijs leaves
 * `parsedValue` undefined.
 *
 * The OID is recognised, so a check that only compares OIDs waves it through
 * — the RFC 5280 §6.1.2 "cannot process" case for an extension whose *name*
 * is known.
 */
export const unparseableCriticalKeyUsage = (): pkijs.Extension =>
	new pkijs.Extension({
		extnID: OID.keyUsage,
		critical: true,
		extnValue: new Uint8Array([0xff, 0xff, 0xff]).buffer as ArrayBuffer,
	});

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

/**
 * An extension whose OID nothing recognises, marked non-critical — which RFC
 * 5280 §5.2 (for a CRL) and §4.2 (for a certificate) let a validator ignore.
 */
export const unknownNonCriticalExtension = (): pkijs.Extension =>
	new pkijs.Extension({
		extnID: "1.3.6.1.4.1.99999.1.2",
		critical: false,
		extnValue: new asn1js.OctetString({ valueHex: new Uint8Array([4, 5, 6]).buffer }).toBER(false),
	});

// ---------------------------------------------------------------------------
// CRL extensions
// ---------------------------------------------------------------------------

/**
 * `deltaCRLIndicator` (RFC 5280 §5.2.4), CRITICAL as the RFC requires: the CRL
 * lists only what changed since base CRL number `baseCrlNumber`.
 */
export const deltaCrlIndicator = (baseCrlNumber: number): pkijs.Extension =>
	new pkijs.Extension({
		extnID: OID.deltaCRLIndicator,
		critical: true,
		extnValue: new asn1js.Integer({ value: baseCrlNumber }).toBER(false),
	});

export interface IssuingDistributionPointOptions {
	/** Scope the CRL to the certificates that name this distribution point. */
	readonly distributionPointUrl?: string;
	readonly onlyContainsUserCerts?: boolean;
	readonly onlyContainsCACerts?: boolean;
	/** A `ReasonFlags` octet; the CRL covers only these reason codes. */
	readonly onlySomeReasons?: number;
	readonly indirectCRL?: boolean;
}

/** `issuingDistributionPoint` (RFC 5280 §5.2.5), CRITICAL as the RFC requires. */
export const issuingDistributionPoint = (opts: IssuingDistributionPointOptions): pkijs.Extension =>
	new pkijs.Extension({
		extnID: OID.issuingDistributionPoint,
		critical: true,
		extnValue: new pkijs.IssuingDistributionPoint({
			...(opts.distributionPointUrl === undefined
				? {}
				: { distributionPoint: [uriName(opts.distributionPointUrl)] }),
			onlyContainsUserCerts: opts.onlyContainsUserCerts ?? false,
			onlyContainsCACerts: opts.onlyContainsCACerts ?? false,
			...(opts.onlySomeReasons === undefined ? {} : { onlySomeReasons: opts.onlySomeReasons }),
			indirectCRL: opts.indirectCRL ?? false,
			onlyContainsAttributeCerts: false,
		})
			.toSchema()
			.toBER(false),
	});

/**
 * `certificateIssuer` (RFC 5280 §5.3.3) — a CRL *entry* extension, CRITICAL,
 * stating that the entry and those after it were issued by someone other
 * than the CRL issuer. Only meaningful inside an indirect CRL.
 */
export const certificateIssuerEntryExtension = (cn: string): pkijs.Extension => {
	const name = new pkijs.RelativeDistinguishedNames();
	setCommonName(name, cn);
	return new pkijs.Extension({
		extnID: OID.certificateIssuer,
		critical: true,
		extnValue: new pkijs.GeneralNames({ names: [new pkijs.GeneralName({ type: 4, value: name })] })
			.toSchema()
			.toBER(false),
	});
};

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
	/** The CRL's own extensions (`crlExtensions`). */
	readonly extensions?: readonly pkijs.Extension[];
	/** CRL *entry* extensions, attached to every revoked entry. */
	readonly entryExtensions?: readonly pkijs.Extension[];
	/** Digest for the signature. `"SHA-1"` exercises the algorithm policy on revocation material (#470). */
	readonly hash?: "SHA-256" | "SHA-1";
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
					...(options.entryExtensions === undefined
						? {}
						: {
								crlEntryExtensions: new pkijs.Extensions({
									extensions: [...options.entryExtensions],
								}),
							}),
				}),
		);
	}
	if (options.extensions !== undefined && options.extensions.length > 0) {
		crl.crlExtensions = new pkijs.Extensions({ extensions: [...options.extensions] });
	}
	await crl.sign(
		(options.signingKeys ?? options.issuer.keys).privateKey,
		options.hash ?? "SHA-256",
		crypto,
	);
	return new Uint8Array(crl.toSchema(true).toBER(false));
};

// ---------------------------------------------------------------------------
// OCSP (#431)
// ---------------------------------------------------------------------------

/**
 * A delegated OCSP responder certificate issued by `issuer`: an end entity
 * with `id-kp-OCSPSigning` and `id-pkix-ocsp-nocheck`. Override `extensions`
 * to mint one that lacks either.
 */
export const mintOcspResponder = (
	cn: string,
	serial: number,
	issuer: Minted,
	extra: Partial<MintOptions> = {},
): Promise<Minted> =>
	mint({
		cn,
		serial,
		issuer,
		extensions: [
			basicConstraints(false),
			keyUsage(KEY_USAGE.digitalSignature),
			ocspSigningEku(),
			ocspNoCheck(),
		],
		...extra,
	});

/** `OCSPResponseStatus` values (RFC 6960 §4.2.1). */
export const OCSP_RESPONSE_STATUS = {
	successful: 0,
	malformedRequest: 1,
	internalError: 2,
	tryLater: 3,
	sigRequired: 5,
	unauthorized: 6,
} as const;

/**
 * The nonce a DER `OCSPRequest` carries, as the extension's `extnValue`
 * bytes — what a responder echoes back verbatim (RFC 6960 §4.4.1).
 */
export const nonceOf = (requestDer: Uint8Array): Uint8Array | undefined => {
	const request = pkijs.OCSPRequest.fromBER(requestDer);
	const extension = request.tbsRequest.requestExtensions?.find(
		(ext) => ext.extnID === OID.ocspNonce,
	);
	return extension === undefined
		? undefined
		: new Uint8Array(extension.extnValue.valueBlock.valueHexView);
};

/** A nonce extension carrying exactly `extnValue` — the bytes a request's `nonceOf` returned. */
export const ocspNonceExtension = (extnValue: Uint8Array): pkijs.Extension =>
	new pkijs.Extension({
		extnID: OID.ocspNonce,
		critical: false,
		extnValue: extnValue.slice().buffer as ArrayBuffer,
	});

export interface MintOcspResponseOptions {
	/** The CA that issued `subject`; the default signer, and what the `CertID` hashes. */
	readonly issuer: Minted;
	/** The certificate the single response is about. */
	readonly subject: Minted;
	readonly status?: "good" | "revoked" | "unknown";
	readonly revokedAt?: Date;
	/** A `CRLReason` value (RFC 5280 §5.3.1). */
	readonly revocationReason?: number;
	readonly thisUpdate?: Date;
	/** `null` omits `nextUpdate` altogether. */
	readonly nextUpdate?: Date | null;
	readonly producedAt?: Date;
	/** The nonce `extnValue` to echo; omit for a response with no nonce. */
	readonly nonce?: Uint8Array;
	/** Who signs — a delegated responder, or a stranger. Defaults to `issuer`. */
	readonly signer?: Minted;
	/** Attach the signer's certificate in `certs`. Defaults to true when the signer is not `issuer`. */
	readonly attachSignerCertificate?: boolean;
	/** Identify the responder `byKey` (SHA-1 of its public key) rather than `byName`. */
	readonly responderIdByKey?: boolean;
	/** Hash algorithm of the `CertID` in the single response. Defaults to SHA-1. */
	readonly certIdHash?: "SHA-1" | "SHA-256";
	/** Build the `CertID` for this certificate instead of `subject` — a response about someone else. */
	readonly certIdFor?: Minted;
	readonly responseExtensions?: readonly pkijs.Extension[];
	readonly singleExtensions?: readonly pkijs.Extension[];
	/** A non-`successful` status yields an `OCSPResponse` with no `responseBytes`. */
	readonly responseStatus?: number;
	/** Sign with this key instead of the signer's own. */
	readonly signingKeys?: CryptoKeyPair;
	/** Digest for the response signature. `"SHA-1"` exercises the algorithm policy on revocation material (#470). */
	readonly hash?: "SHA-256" | "SHA-1";
}

const certStatusOf = (options: MintOcspResponseOptions): asn1js.BaseBlock => {
	switch (options.status ?? "good") {
		case "good":
			return new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 } });
		case "unknown":
			return new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 2 } });
		case "revoked":
			return new asn1js.Constructed({
				idBlock: { tagClass: 3, tagNumber: 1 },
				value: [
					new asn1js.GeneralizedTime({ valueDate: options.revokedAt ?? DEFAULT_NOT_BEFORE }),
					...(options.revocationReason === undefined
						? []
						: [
								new asn1js.Constructed({
									idBlock: { tagClass: 3, tagNumber: 0 },
									value: [new asn1js.Enumerated({ value: options.revocationReason })],
								}),
							]),
				],
			});
	}
};

/** Returns the DER bytes of an `OCSPResponse`. */
export const mintOcspResponse = async (options: MintOcspResponseOptions): Promise<Uint8Array> => {
	const crypto = engine();
	const responseStatus = options.responseStatus ?? OCSP_RESPONSE_STATUS.successful;
	if (responseStatus !== OCSP_RESPONSE_STATUS.successful) {
		const failed = new pkijs.OCSPResponse({
			responseStatus: new asn1js.Enumerated({ value: responseStatus }),
		});
		return new Uint8Array(failed.toSchema().toBER(false));
	}

	const signer = options.signer ?? options.issuer;
	const certID = await pkijs.CertID.create(
		(options.certIdFor ?? options.subject).cert,
		{ hashAlgorithm: options.certIdHash ?? "SHA-1", issuerCertificate: options.issuer.cert },
		crypto,
	);
	const single = new pkijs.SingleResponse({
		certID,
		certStatus: certStatusOf(options),
		thisUpdate: options.thisUpdate ?? new Date("2026-12-31T23:00:00Z"),
		...(options.nextUpdate === null
			? {}
			: { nextUpdate: options.nextUpdate ?? new Date("2027-01-02T00:00:00Z") }),
		...(options.singleExtensions === undefined
			? {}
			: { singleExtensions: [...options.singleExtensions] }),
	});

	const responderID = options.responderIdByKey
		? new asn1js.OctetString({
				valueHex: await crypto.digest(
					{ name: "SHA-1" },
					signer.cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView,
				),
			})
		: signer.cert.subject;
	const responseExtensions = [
		...(options.nonce === undefined ? [] : [ocspNonceExtension(options.nonce)]),
		...(options.responseExtensions ?? []),
	];
	const tbsResponseData = new pkijs.ResponseData({
		responderID,
		producedAt: options.producedAt ?? options.thisUpdate ?? new Date("2026-12-31T23:00:00Z"),
		responses: [single],
		...(responseExtensions.length === 0 ? {} : { responseExtensions }),
	});

	const attach = options.attachSignerCertificate ?? signer !== options.issuer;
	const basic = new pkijs.BasicOCSPResponse({
		tbsResponseData,
		...(attach ? { certs: [signer.cert] } : {}),
	});
	await basic.sign(
		(options.signingKeys ?? signer.keys).privateKey,
		options.hash ?? "SHA-256",
		crypto,
	);

	const response = new pkijs.OCSPResponse({
		responseStatus: new asn1js.Enumerated({ value: responseStatus }),
		responseBytes: new pkijs.ResponseBytes({
			responseType: OID.ocspBasic,
			response: new asn1js.OctetString({ valueHex: basic.toSchema().toBER(false) }),
		}),
	});
	return new Uint8Array(response.toSchema().toBER(false));
};
