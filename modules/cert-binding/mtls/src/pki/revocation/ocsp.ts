import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
	decoded,
	generalName,
	isHold,
	keyUsageAllows,
	oid,
	parsedExtension,
	same,
	usage,
} from "../der.ts";
import { hasMalformedExtension, hasUnknownCritical, rsaBits } from "../path.ts";
import { isStrong, signedBy } from "../signatures.ts";

/**
 * What a responder says of one certificate, until its next update or its signer's end; a delegated
 * responder, unless it says it needs no check, is handed back to be checked. Or busy, or unusable.
 */
export type Answer =
	| {
			readonly kind: "good" | "revoked" | "unknown";
			readonly until: number;
			/** Revoked on hold, which can be lifted. */
			readonly held?: boolean;
			readonly responder?: pkijs.Certificate;
	  }
	| { readonly kind: "busy" }
	| { readonly kind: "unusable"; readonly reason: string };

export interface Asked {
	readonly now: number;
	/** How far ahead an answer's this update may be. */
	readonly skewMs: number;
	/** How long an answer without a next update is taken. */
	readonly freshMs: number;
	/** The smallest RSA key a delegated responder may sign with, as on the path. */
	readonly minRsaBits: number;
	/** The nonce the request carried; the answer must carry it back. */
	readonly nonce?: Uint8Array;
}

const ocspAccess = "1.3.6.1.5.5.7.48.1";
const ocspSigning = "1.3.6.1.5.5.7.3.9";
const statuses = ["good", "revoked", "unknown"] as const;
const responseStatus = { successful: 0, internalError: 2, tryLater: 3 } as const;

/** Where a certificate's OCSP responder is: its http and https OCSP access locations. */
export function ocspUrlsOf(cert: pkijs.Certificate): readonly string[] {
	const access = parsedExtension<pkijs.InfoAccess>(cert, oid.authorityInfoAccess);
	return (access?.accessDescriptions ?? [])
		.filter((d) => d.accessMethod === ocspAccess && d.accessLocation.type === generalName.uri)
		.map((d) => d.accessLocation.value as string)
		.filter((url) => /^https?:\/\//i.test(url));
}

// The certificate is named by SHA-1 hashes, as responders expect; they identify, they sign nothing.
async function idOf(cert: pkijs.Certificate, issuer: pkijs.Certificate): Promise<pkijs.CertID> {
	const id = new pkijs.CertID();
	await id.createForCertificate(cert, { hashAlgorithm: "SHA-1", issuerCertificate: issuer });
	return id;
}

/** A request about the certificate, carrying the nonce where one is given. */
export async function ocspRequestOf(
	cert: pkijs.Certificate,
	issuer: pkijs.Certificate,
	nonce: Uint8Array | undefined,
): Promise<Uint8Array> {
	const request = new pkijs.OCSPRequest();
	request.tbsRequest.requestList = [new pkijs.Request({ reqCert: await idOf(cert, issuer) })];
	if (nonce) {
		const value = new asn1js.OctetString({ valueHex: nonce }).toBER(false);
		request.tbsRequest.requestExtensions = [
			new pkijs.Extension({ extnID: oid.ocspNonce, extnValue: value }),
		];
	}
	return new Uint8Array(request.toSchema(true).toBER(false));
}

/** Whether the issuer delegated its answers to `cert`, as of the time asked, under the path's key rules. */
async function isDelegated(
	cert: pkijs.Certificate,
	issuer: pkijs.Certificate,
	asked: Asked,
): Promise<boolean> {
	// Before any extension's parsed value is read below.
	if (hasUnknownCritical(cert) || hasMalformedExtension(cert)) return false;
	if (!keyUsageAllows(cert, usage.digitalSignature)) return false;
	const bits = rsaBits(cert);
	if (bits !== undefined && bits < asked.minRsaBits) return false;
	if (!cert.issuer.isEqual(issuer.subject) || !isStrong(cert.signatureAlgorithm)) return false;
	const { now } = asked;
	if (now < cert.notBefore.value.getTime() || cert.notAfter.value.getTime() < now) return false;
	const eku = parsedExtension<pkijs.ExtKeyUsage>(cert, oid.extKeyUsage);
	if (!eku?.keyPurposes.includes(ocspSigning)) return false;
	return signedBy(issuer, cert.tbsView, cert.signatureValue, cert.signatureAlgorithm);
}

/** The certificate the response names as its signer: the issuer, or one it delegated to. */
async function signerOf(basic: pkijs.BasicOCSPResponse, issuer: pkijs.Certificate, asked: Asked) {
	const id: unknown = basic.tbsResponseData.responderID;
	const identifies = async (cert: pkijs.Certificate) => {
		if (id instanceof pkijs.RelativeDistinguishedNames) return id.isEqual(cert.subject);
		if (!(id instanceof asn1js.OctetString)) return false;
		const key = cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView;
		const hashed = new Uint8Array(await crypto.subtle.digest("SHA-1", new Uint8Array(key)));
		return same(id.valueBlock.valueHexView, hashed);
	};
	if (await identifies(issuer)) return issuer;
	for (const cert of basic.certs ?? []) {
		if (await identifies(cert)) return (await isDelegated(cert, issuer, asked)) ? cert : undefined;
	}
	return undefined;
}

/** A revoked status's CRLReason, where it gives one (RFC 6960 §4.2.1). */
function reasonOf(status: asn1js.BaseBlock) {
	const inner = status instanceof asn1js.Constructed ? status.valueBlock.value : [];
	const given = inner.find(
		(block) => block.idBlock.tagClass === 3 && block.idBlock.tagNumber === 0,
	);
	return given instanceof asn1js.Constructed ? given.valueBlock.value[0] : undefined;
}

function echoes(extensions: readonly pkijs.Extension[], nonce: Uint8Array): boolean {
	const echoed = extensions.find((e) => e.extnID === oid.ocspNonce);
	const value = echoed && asn1js.fromBER(echoed.extnValue.valueBlock.valueHexView).result;
	return value instanceof asn1js.OctetString && same(value.valueBlock.valueHexView, nonce);
}

/** What the response says of `cert`; nothing in it is used before its signer's signature is checked. */
export async function judgeOcsp(
	der: Uint8Array,
	cert: pkijs.Certificate,
	issuer: pkijs.Certificate,
	asked: Asked,
): Promise<Answer> {
	const unusable = (reason: string): Answer => ({ kind: "unusable", reason });
	const response = decoded(der, (schema) => new pkijs.OCSPResponse({ schema }));
	if (!response) return unusable("malformed");
	const answered = response.responseStatus.valueBlock.valueDec;
	if (answered === responseStatus.internalError || answered === responseStatus.tryLater) {
		return { kind: "busy" };
	}
	if (answered !== responseStatus.successful) return unusable("status");
	const bytes = response.responseBytes;
	if (bytes?.responseType !== pkijs.id_PKIX_OCSP_Basic) return unusable("malformed");
	// The inner response is read as the engine reads it, bytes past its end ignored.
	let basic: pkijs.BasicOCSPResponse;
	try {
		const inner = asn1js.fromBER(bytes.response.valueBlock.valueHexView);
		basic = new pkijs.BasicOCSPResponse({ schema: inner.result });
	} catch {
		return unusable("malformed");
	}
	if (!isStrong(basic.signatureAlgorithm)) return unusable("signature algorithm");
	const signer = await signerOf(basic, issuer, asked);
	if (!signer) return unusable("signer");
	const data = basic.tbsResponseData;
	if (!(await signedBy(signer, data.tbsView, basic.signature, basic.signatureAlgorithm))) {
		return unusable("signature");
	}
	const extensions = data.responseExtensions ?? [];
	if (extensions.some((e) => e.critical)) return unusable("unsupported");
	if (asked.nonce && !echoes(extensions, asked.nonce)) return unusable("nonce");
	const id = await idOf(cert, issuer);
	const single = data.responses.find((response) => response.certID.isEqual(id));
	if (!single) return unusable("not answered");
	if (single.singleExtensions?.some((e) => e.critical)) return unusable("unsupported");
	const thisUpdate = single.thisUpdate.getTime();
	const until = Math.min(
		single.nextUpdate?.getTime() ?? thisUpdate + asked.freshMs,
		signer.notAfter.value.getTime(),
	);
	if (until < asked.now) return unusable("stale");
	if (thisUpdate > asked.now + asked.skewMs) return unusable("not yet");
	const status = single.certStatus as asn1js.BaseBlock;
	// The engine reads no status but its three tags.
	const kind = statuses[status.idBlock.tagNumber];
	if (!kind) return unusable("malformed");
	const said = { kind, until, held: kind === "revoked" && isHold(reasonOf(status)) };
	const noCheck = parsedExtension<unknown>(signer, oid.ocspNoCheck);
	const checked = signer === issuer || noCheck instanceof asn1js.Null;
	return checked ? said : { ...said, responder: signer };
}
