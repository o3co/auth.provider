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
 * OCSP (RFC 6960) status lookup, verification and caching for
 * `mode = "full-pki"` — the item #341 left open, closed by #431.
 *
 * `pkijs` can encode an `OCSPRequest` and decode an `OCSPResponse`; it does
 * not go and ask a responder, and what it offers for judging the answer is
 * not used here. Everything between "this certificate names a responder" and
 * "here is a status that responder actually vouched for" lives in this file:
 * reading `authorityInfoAccess`, building the request, POSTing it under the
 * guards in `fetchGuard.mts`, **verifying who signed the answer**, matching
 * the nonce, judging freshness, and caching so a busy token endpoint does not
 * ask per request.
 *
 * ### Responder fetch only
 *
 * #341 assumed a stapled response would be the cheap path under the
 * `tls-layer` source. It is not available: `status_request` stapling covers
 * the *server's* certificate, and Node exposes no stapled response for a
 * **client** certificate on the server side. So this arm always asks the
 * responder, with the same two layers CRL fetching has — path validation
 * first, then the host allowlist — because a responder URL is a destination
 * chosen by whoever minted the certificate, exactly as a distribution point
 * is. A certificate that carries OCSP must-staple (RFC 7633) is refused for
 * the same reason, by `checkMustStaple` below: its own requirement cannot be
 * met here, and "unstapled" is not what it asked for.
 *
 * ### Why the answer is verified here and not by pkijs
 *
 * `BasicOCSPResponse.verify` locates the signer among the attached
 * certificates, builds a chain to whatever `trustedCerts` it is given, and
 * checks the signature. It does not check `id-kp-OCSPSigning`, so any
 * certificate the CA ever issued — a client certificate, say — could sign a
 * "good" for itself; and `getCertificateStatus` answers `unknown` for a
 * response that is not about the certificate at all, which is the same
 * answer as a responder that genuinely does not know it. Both are the wrong
 * shape for a decision whose whole point is that "the responder did not
 * vouch for this" and "the responder said good" must never coincide. The
 * rules of RFC 6960 §4.2.2.2 are therefore applied directly: a response is
 * believed only when signed by the issuing CA itself, or by a responder
 * certificate that CA issued which carries `id-kp-OCSPSigning`, is within
 * its validity period, and carries no critical extension this validator
 * does not process. `id-pkix-ocsp-nocheck` (§4.2.2.2.1) is honoured; when a
 * responder certificate lacks it, its own revocation status is not checked —
 * the responder cannot be asked about itself, and the only independent
 * source, a CRL, exists only under `mode = "both"`. Local policy per
 * §4.2.2.2.1's third option, and recorded in the README.
 *
 * ### The algorithm policy applies to the answer too (#470)
 *
 * pkijs verifies `sha1WithRSAEncryption` and `ecdsa-with-SHA1` as readily
 * as it verifies SHA-256, so a SHA-1-signed "good" was believed about a
 * certificate that a SHA-1 signature would have refused on the path. The
 * policy `validate.mts` holds the path to is applied here to the two things
 * an answer introduces that the path pass never saw: the response's own
 * `signatureAlgorithm`, checked on the bytes' shape before the signer is
 * even identified, and — for a delegated responder — the responder
 * certificate, held to the full policy (signature algorithm and RSA modulus)
 * once the checks above have established it is this CA's delegate, so that
 * a stranger's certificate is still refused as *not issued*, whatever it was
 * signed with. Either is `algorithm_not_permitted`, and is remembered per
 * certificate for the negative window like `unsupported_critical_extension`,
 * not exempted like `bad_signature`: the decision is on an OID or a key
 * size, not on whether a signature verifies, so an injected response can
 * pin at most a bounded refusal (an injected `unparseable` already can), and
 * the algorithm is a property of the responder's own material, identical on
 * every request until the CA changes it. Per certificate rather than per
 * responder because a responder may sign with more than one key during a
 * rollover, and the answer is remembered at the granularity it was given —
 * as a stale or `unknown` answer is. The CA's own key, when the CA signs the
 * response itself, is on the validated path and was judged there.
 *
 * ### The CertID hash
 *
 * The `CertID` names the certificate by a hash of its issuer's name and key
 * (§4.1.1). SHA-1 is used for it: this is a lookup identifier the responder
 * uses to find a record, not a signature, and responders universally answer
 * it where a SHA-256 `CertID` is often answered `unauthorized`. Nothing
 * about it touches the algorithm policy in `algorithms.mts`, which governs
 * what may *sign* — and a response identifying the certificate by another
 * hash is matched by recomputing, not refused on the OID.
 *
 * ### The nonce
 *
 * Every request carries a 16-byte nonce (§4.4.1; RFC 8954 bounds it to
 * 1..32). A response that echoes a different one is refused and never
 * cached: it is a replay or a broken responder, and either way not this
 * request's answer. A response with no nonce is refused by default — without
 * it, a "good" captured before a revocation replays until its `nextUpdate` —
 * and accepted only when `requireNonce: false` states that the deployment's
 * responder pre-produces answers, in which case the response's own
 * `thisUpdate`/`nextUpdate` window is the only thing binding it in time.
 *
 * ### Freshness
 *
 * `thisUpdate` may lead this process's clock by `OCSP_CLOCK_SKEW_MS`; a
 * `nextUpdate` that has passed is stale with no allowance, as a CRL's is. A
 * response with no `nextUpdate` is, per §4.2.2.1, one whose newer version is
 * "available all the time" — not one that is valid forever — so it is used
 * for `OCSP_UNDATED_RESPONSE_MAX_AGE_MS` from its `thisUpdate` and no longer.
 *
 * ### `unknown` is not `good`
 *
 * §2.2 defines `unknown` as "the responder doesn't know about the certificate
 * being requested". It is reported as unavailable, so that `on-unavailable`
 * applies, rather than read as "not revoked": a responder that lost its
 * database would otherwise un-revoke everything.
 *
 * ### One request per certificate, not one per caller
 *
 * The caching shape is `crl.mts`'s, keyed per certificate rather than per
 * URL because an OCSP answer is about one certificate: concurrent lookups of
 * the same certificate share one in-flight request; a good or revoked answer
 * is kept until its `nextUpdate` or `cache-ttl-seconds`, whichever is
 * sooner; a responder that could not be used is remembered as down for
 * `OCSP_NEGATIVE_CACHE_TTL_MS` (per responder for a transport or
 * responder-level failure, per certificate for an answer that could not be
 * used, `algorithm_not_permitted` included); `bad_signature` and
 * `nonce_mismatch` are never remembered in either direction, for the reason
 * `crl.mts` gives.
 */

import { createHash, randomBytes, X509Certificate } from "node:crypto";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
	type AlgorithmPolicy,
	checkAlgorithmPolicy,
	checkSignatureAlgorithm,
} from "./algorithms.mjs";
import {
	type CriticalExtensionCheck,
	checkCriticalExtensions,
	checkOcspCriticalExtensions,
	extensionValueParsed,
} from "./criticalExtensions.mjs";
import { CRL_NEGATIVE_CACHE_TTL_MS } from "./crl.mjs";
import type { GuardedFetch } from "./fetchGuard.mjs";

/** OID of `authorityInfoAccess` (RFC 5280 §4.2.2.1). */
const OID_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1";
/** `id-ad-ocsp` access method. */
const OID_AD_OCSP = "1.3.6.1.5.5.7.48.1";
/** `id-pkix-ocsp-basic` response type (RFC 6960 §4.2.1). */
const OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1";
/** `id-pkix-ocsp-nonce` (RFC 6960 §4.4.1). */
const OID_OCSP_NONCE = "1.3.6.1.5.5.7.48.1.2";
/** `id-kp-OCSPSigning` (RFC 6960 §4.2.2.2). */
const OID_KP_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";
/** `extendedKeyUsage` (RFC 5280 §4.2.1.12). */
const OID_EXT_KEY_USAGE = "2.5.29.37";
/** The TLS feature extension (RFC 7633). */
const OID_TLS_FEATURE = "1.3.6.1.5.5.7.1.24";
/** SHA-1, the `CertID` hash. */
const OID_SHA1 = "1.3.14.3.2.26";
/** `GeneralName` tag for `uniformResourceIdentifier`. */
const GENERAL_NAME_URI = 6;
/** TLS extension types that mean OCSP must-staple (RFC 7633 §4.2.3.1). */
const TLS_FEATURE_STATUS_REQUEST = 5;
const TLS_FEATURE_STATUS_REQUEST_V2 = 17;
/** RFC 8954 §2.1 bounds the nonce to 1..32 bytes. */
const NONCE_BYTES = 16;

const OCSP_REQUEST_MEDIA_TYPE = "application/ocsp-request";
const OCSP_RESPONSE_MEDIA_TYPE = "application/ocsp-response";

/**
 * How long a responder that could not be used is remembered, in
 * milliseconds. The CRL resolver's window, for the CRL resolver's reasons.
 */
export const OCSP_NEGATIVE_CACHE_TTL_MS = CRL_NEGATIVE_CACHE_TTL_MS;

/**
 * How far a response's `thisUpdate` may lead this process's clock. Five
 * minutes is the conventional allowance; a responder signing on demand must
 * not be refused for a clock a few seconds ahead, and a response dated
 * further ahead than this is not describing the present.
 */
export const OCSP_CLOCK_SKEW_MS = 5 * 60_000;

/**
 * How long a response with no `nextUpdate` is used for, from its
 * `thisUpdate`. RFC 6960 §4.2.2.1: absence means newer information is
 * available all the time — an instruction to ask again soon, not a licence
 * to keep the answer. Ten minutes absorbs the skew allowance twice over and
 * stays in the same order of magnitude as the negative window.
 */
export const OCSP_UNDATED_RESPONSE_MAX_AGE_MS = 10 * 60_000;

/**
 * Why a certificate's status could not be determined by OCSP. Values are
 * stable — audit logs read them. `algorithm_not_permitted` is a response, or
 * a delegated responder's certificate, outside the algorithm policy the path
 * is held to (#470).
 */
export type OcspUnavailableReason =
	| "no_responder"
	| "fetch_failed"
	| "unparseable"
	| "responder_error"
	| "no_matching_response"
	| "unsupported_critical_extension"
	| "algorithm_not_permitted"
	| "bad_signature"
	| "nonce_mismatch"
	| "nonce_missing"
	| "not_yet_valid"
	| "stale"
	| "unknown";

export type OcspCertificateStatus =
	| { readonly status: "good" }
	| {
			readonly status: "revoked";
			readonly revokedAt: Date;
			/** The `CRLReason` name, when the responder gave one. */
			readonly reason: string | undefined;
	  };

export type OcspLookup =
	| {
			readonly ok: true;
			/** The responder whose answer this is. */
			readonly responder: string;
			readonly status: OcspCertificateStatus;
	  }
	| { readonly ok: false; readonly reason: OcspUnavailableReason; readonly detail: string };

export type OcspResponders =
	| { readonly ok: true; readonly urls: readonly string[] }
	| { readonly ok: false; readonly reason: "no_responder"; readonly detail: string };

const isHttpUrl = (value: string): boolean => /^https?:\/\//i.test(value);

/**
 * The OCSP responders a certificate advertises, in the order listed. RFC
 * 5280 §4.2.2.1 lets a CA list several; they are tried in turn until one
 * yields an answer that can be used. Only absolute HTTP(S) URIs are kept —
 * a certificate left with none is `no_responder`, the OCSP twin of
 * `no_distribution_point`: an honest "cannot check", not a silent pass.
 */
export const ocspResponders = (certificate: pkijs.Certificate): OcspResponders => {
	const extension = certificate.extensions?.find((ext) => ext.extnID === OID_AUTHORITY_INFO_ACCESS);
	const parsed = extension?.parsedValue as pkijs.InfoAccess | undefined;
	const urls = (parsed?.accessDescriptions ?? [])
		.filter((description) => description.accessMethod === OID_AD_OCSP)
		.filter((description) => description.accessLocation.type === GENERAL_NAME_URI)
		.map((description) => description.accessLocation.value)
		.filter((value): value is string => typeof value === "string" && isHttpUrl(value));
	if (urls.length === 0) {
		return {
			ok: false,
			reason: "no_responder",
			detail: "certificate advertises no id-ad-ocsp HTTP(S) URI in authorityInfoAccess",
		};
	}
	return { ok: true, urls };
};

/**
 * RFC 7633: a certificate carrying the TLS feature extension with
 * `status_request` (or `status_request_v2`) requires a stapled OCSP response
 * in the handshake it is used in. Node presents no stapled response for a
 * client certificate, so the requirement cannot be met by this server, and
 * the certificate is refused — under every revocation mode, `disabled`
 * included, because the demand is the certificate's own, not the
 * operator's. Other feature numbers name nothing this validator can judge
 * and are ignored; a value that cannot be decoded is a demand that cannot
 * be read, and is refused whether or not the extension is critical.
 */
export const checkMustStaple = (leaf: pkijs.Certificate): CriticalExtensionCheck => {
	const extension = leaf.extensions?.find((ext) => ext.extnID === OID_TLS_FEATURE);
	if (extension === undefined) return { ok: true };
	const unparseable: CriticalExtensionCheck = {
		ok: false,
		step: "unparseable TLS feature extension",
		detail:
			"the leaf carries a TLS feature extension (RFC 7633) whose value could not be " +
			"decoded, so the requirement it states cannot be honoured",
	};
	const decoded = asn1js.fromBER(extension.extnValue.valueBlock.valueHexView);
	if (decoded.offset === -1 || !(decoded.result instanceof asn1js.Sequence)) return unparseable;
	const features: number[] = [];
	for (const item of decoded.result.valueBlock.value) {
		if (!(item instanceof asn1js.Integer)) return unparseable;
		features.push(item.valueBlock.valueDec);
	}
	if (
		features.includes(TLS_FEATURE_STATUS_REQUEST) ||
		features.includes(TLS_FEATURE_STATUS_REQUEST_V2)
	) {
		return {
			ok: false,
			step: "OCSP must-staple cannot be satisfied",
			detail:
				"the leaf carries the TLS feature extension (RFC 7633) requiring status_request, " +
				"and no stapled OCSP response can be presented for a client certificate here — " +
				"the certificate's own requirement cannot be met, so it is refused rather than " +
				"treated as unstapled",
		};
	}
	return { ok: true };
};

/** `CRLReason` names (RFC 5280 §5.3.1), for the audit trail. */
const CRL_REASON_NAMES: Readonly<Record<number, string>> = {
	0: "unspecified",
	1: "keyCompromise",
	2: "cACompromise",
	3: "affiliationChanged",
	4: "superseded",
	5: "cessationOfOperation",
	6: "certificateHold",
	8: "removeFromCRL",
	9: "privilegeWithdrawn",
	10: "aACompromise",
};

/** `OCSPResponseStatus` names (RFC 6960 §4.2.1). */
const RESPONSE_STATUS_NAMES: Readonly<Record<number, string>> = {
	0: "successful",
	1: "malformedRequest",
	2: "internalError",
	3: "tryLater",
	5: "sigRequired",
	6: "unauthorized",
};

const equalBytes = (a: Uint8Array, b: Uint8Array): boolean =>
	a.byteLength === b.byteLength && a.every((byte, index) => byte === b[index]);

const describeError = (err: unknown): string => (err instanceof Error ? err.message : String(err));

/** Reasons remembered for the negative window, and at which granularity. */
type RespondersFailure = "fetch_failed" | "unparseable" | "responder_error";
type CertificateFailure =
	| "no_matching_response"
	| "unsupported_critical_extension"
	| "algorithm_not_permitted"
	| "nonce_missing"
	| "not_yet_valid"
	| "stale"
	| "unknown";

const RESPONDER_FAILURES: ReadonlySet<string> = new Set<RespondersFailure>([
	"fetch_failed",
	"unparseable",
	"responder_error",
]);
const CERTIFICATE_FAILURES: ReadonlySet<string> = new Set<CertificateFailure>([
	"no_matching_response",
	"unsupported_critical_extension",
	"algorithm_not_permitted",
	"nonce_missing",
	"not_yet_valid",
	"stale",
	"unknown",
]);

type CacheEntry =
	| {
			readonly kind: "status";
			readonly status: OcspCertificateStatus;
			/** Epoch millis after which the responder must be asked again. */
			readonly expiresAt: number;
	  }
	| {
			readonly kind: "unavailable";
			readonly reason: RespondersFailure | CertificateFailure;
			readonly detail: string;
			/** Epoch millis after which the responder is tried again. */
			readonly expiresAt: number;
	  };

/** What one responder produced for one certificate, after every check. */
type Answer =
	| { readonly ok: true; readonly status: OcspCertificateStatus; readonly expiresAt: number }
	| { readonly ok: false; readonly reason: OcspUnavailableReason; readonly detail: string };

export interface OcspResolverOptions {
	readonly fetch: GuardedFetch;
	/**
	 * Upper bound on how long an answer is reused, in seconds. The response's
	 * own `nextUpdate` still wins when it is sooner.
	 */
	readonly cacheTtlSeconds: number;
	/**
	 * The signature-algorithm and key-size policy the validated path is held
	 * to, applied to the response's signature and to a delegated responder's
	 * certificate as well (#470). See the module header.
	 */
	readonly algorithms: AlgorithmPolicy;
	/**
	 * Refuse a response that does not carry the request's nonce. Defaults to
	 * `true`; see the module header for what `false` gives up.
	 */
	readonly requireNonce?: boolean;
	/** Bound on cache size. Entries are per certificate, so the default is roomier than the CRL cache's. */
	readonly maxCacheEntries?: number;
}

export interface OcspResolver {
	/**
	 * Ask the responders `certificate` names about it, verifying each answer
	 * against `issuer`, the certificate that issued it — the next element up
	 * the validated path. Only an answer whose signer is that issuer, or a
	 * responder that issuer delegated to, is ever returned or cached.
	 */
	resolve(
		certificate: pkijs.Certificate,
		issuer: pkijs.Certificate,
		now: Date,
	): Promise<OcspLookup>;
	/** Entry count, usable and remembered-unavailable alike — for tests and for a future metric. */
	size(): number;
}

const DEFAULT_MAX_CACHE_ENTRIES = 1024;

const issuerKeyId = (issuer: pkijs.Certificate): string =>
	createHash("sha256")
		.update(new Uint8Array(issuer.subjectPublicKeyInfo.toSchema().toBER(false)))
		.digest("hex");

const serialHex = (certificate: pkijs.Certificate): string =>
	Buffer.from(certificate.serialNumber.valueBlock.valueHexView).toString("hex");

/** Node's view of a certificate — what `checkAlgorithmPolicy` reads the key size from. */
const toNode = (certificate: pkijs.Certificate): X509Certificate =>
	new X509Certificate(Buffer.from(certificate.toSchema(true).toBER(false)));

/** Why a signer was refused: a signature that is not the CA's, or material outside the policy. */
type SignerRefusal = {
	readonly ok: false;
	readonly reason: "bad_signature" | "algorithm_not_permitted";
	readonly detail: string;
};

interface BuiltRequest {
	readonly der: Uint8Array;
	readonly certId: pkijs.CertID;
	/** The nonce extension's `extnValue` — the bytes the responder must echo. */
	readonly nonce: Uint8Array;
}

const buildRequest = async (
	certificate: pkijs.Certificate,
	issuer: pkijs.Certificate,
	crypto: pkijs.ICryptoEngine,
): Promise<BuiltRequest> => {
	const certId = await pkijs.CertID.create(
		certificate,
		{ hashAlgorithm: "SHA-1", issuerCertificate: issuer },
		crypto,
	);
	// A fresh copy: `randomBytes` may hand back a slice of a pooled buffer,
	// and the ASN.1 encoder reads the whole underlying `ArrayBuffer`.
	const random = new Uint8Array(randomBytes(NONCE_BYTES));
	const nonce = new Uint8Array(
		new asn1js.OctetString({ valueHex: random.buffer as ArrayBuffer }).toBER(false),
	);
	const request = new pkijs.OCSPRequest({
		tbsRequest: new pkijs.TBSRequest({
			requestList: [new pkijs.Request({ reqCert: certId })],
			requestExtensions: [
				new pkijs.Extension({
					extnID: OID_OCSP_NONCE,
					critical: false,
					extnValue: nonce.slice().buffer as ArrayBuffer,
				}),
			],
		}),
	});
	return { der: new Uint8Array(request.toSchema(true).toBER(false)), certId, nonce };
};

type Parsed =
	| { readonly ok: true; readonly basic: pkijs.BasicOCSPResponse }
	| {
			readonly ok: false;
			readonly reason: "unparseable" | "responder_error";
			readonly detail: string;
	  };

const parseResponse = (bytes: Uint8Array): Parsed => {
	let response: pkijs.OCSPResponse;
	try {
		response = pkijs.OCSPResponse.fromBER(bytes);
	} catch (err) {
		return {
			ok: false,
			reason: "unparseable",
			detail: `not a DER OCSPResponse (${describeError(err)})`,
		};
	}
	const status = response.responseStatus.valueBlock.valueDec;
	if (status !== 0) {
		return {
			ok: false,
			reason: "responder_error",
			detail: `the responder answered ${RESPONSE_STATUS_NAMES[status] ?? "status"} (${status})`,
		};
	}
	const responseBytes = response.responseBytes;
	if (responseBytes === undefined) {
		return {
			ok: false,
			reason: "unparseable",
			detail: "a successful response with no responseBytes",
		};
	}
	if (responseBytes.responseType !== OID_OCSP_BASIC) {
		return {
			ok: false,
			reason: "unparseable",
			detail: `responseType ${responseBytes.responseType} is not id-pkix-ocsp-basic`,
		};
	}
	try {
		return {
			ok: true,
			basic: pkijs.BasicOCSPResponse.fromBER(responseBytes.response.valueBlock.valueHexView),
		};
	} catch (err) {
		return {
			ok: false,
			reason: "unparseable",
			detail: `not a DER BasicOCSPResponse (${describeError(err)})`,
		};
	}
};

/**
 * The single response about `certificate`, matched by `CertID`. The request
 * asked by SHA-1; a responder that answers by another hash is matched by
 * recomputing the `CertID` with that hash rather than refused on the OID —
 * both name the same issuer and serial.
 */
const findSingleResponse = async (
	basic: pkijs.BasicOCSPResponse,
	certificate: pkijs.Certificate,
	issuer: pkijs.Certificate,
	requested: pkijs.CertID,
	crypto: pkijs.ICryptoEngine,
): Promise<pkijs.SingleResponse | undefined> => {
	const byAlgorithm = new Map<string, pkijs.CertID | null>([[OID_SHA1, requested]]);
	for (const single of basic.tbsResponseData.responses) {
		const oid = single.certID.hashAlgorithm.algorithmId;
		let ours = byAlgorithm.get(oid);
		if (ours === undefined) {
			ours = null;
			try {
				const algorithm = crypto.getAlgorithmByOID<{ name: string }>(
					oid,
					true,
					"CertID.hashAlgorithm",
				);
				ours = await pkijs.CertID.create(
					certificate,
					{ hashAlgorithm: algorithm.name, issuerCertificate: issuer },
					crypto,
				);
			} catch {
				// A hash this engine does not speak cannot identify anything here.
			}
			byAlgorithm.set(oid, ours);
		}
		if (ours !== null && single.certID.isEqual(ours)) return single;
	}
	return undefined;
};

/** Whether `candidate` is the responder `responderID` names — by name, or by SHA-1 of its key. */
const isNamedResponder = async (
	candidate: pkijs.Certificate,
	responderId: unknown,
	crypto: pkijs.ICryptoEngine,
): Promise<boolean> => {
	if (responderId instanceof pkijs.RelativeDistinguishedNames) {
		return candidate.subject.isEqual(responderId);
	}
	if (responderId instanceof asn1js.OctetString) {
		const hash = await crypto.digest(
			{ name: "SHA-1" },
			// `.slice()` copies onto a plain ArrayBuffer — WebCrypto's `BufferSource`
			// refuses a view over a possibly-shared buffer.
			candidate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView.slice(),
		);
		return equalBytes(new Uint8Array(hash), responderId.valueBlock.valueHexView);
	}
	return false;
};

/**
 * RFC 6960 §4.2.2.2: a responder other than the CA itself must hold a
 * certificate that CA issued, carrying `id-kp-OCSPSigning`. "Issued by"
 * means both the name chain and the signature; the EKU is the CA's
 * statement that this key may speak for it about revocation, and without
 * it any end-entity certificate the CA ever issued could un-revoke itself.
 */
const checkDelegatedResponder = async (
	candidate: pkijs.Certificate,
	issuer: pkijs.Certificate,
	now: Date,
	crypto: pkijs.ICryptoEngine,
	algorithms: AlgorithmPolicy,
): Promise<{ ok: true } | SignerRefusal> => {
	const notIssued =
		"the responder certificate was not issued by the certificate's issuing CA (RFC 6960 §4.2.2.2)";
	if (!candidate.issuer.isEqual(issuer.subject)) {
		return { ok: false, reason: "bad_signature", detail: notIssued };
	}
	let issued = false;
	try {
		issued = await candidate.verify(issuer, crypto);
	} catch {
		issued = false;
	}
	if (!issued) return { ok: false, reason: "bad_signature", detail: notIssued };

	if (
		candidate.notBefore.value.getTime() > now.getTime() ||
		candidate.notAfter.value.getTime() < now.getTime()
	) {
		return {
			ok: false,
			reason: "bad_signature",
			detail: "the responder certificate is outside its validity period",
		};
	}

	const eku = candidate.extensions?.find((ext) => ext.extnID === OID_EXT_KEY_USAGE);
	const purposes = (eku?.parsedValue as pkijs.ExtKeyUsage | undefined)?.keyPurposes;
	if (
		eku === undefined ||
		!extensionValueParsed(eku) ||
		purposes === undefined ||
		!purposes.includes(OID_KP_OCSP_SIGNING)
	) {
		return {
			ok: false,
			reason: "bad_signature",
			detail:
				"the responder certificate does not carry id-kp-OCSPSigning in extendedKeyUsage " +
				"(RFC 6960 §4.2.2.2)",
		};
	}

	// RFC 5280 §6.1.2 applies to the responder certificate as to any other;
	// a critical extension nothing here processes is a refusal, not a pass.
	const critical = checkCriticalExtensions([candidate]);
	if (!critical.ok) {
		return {
			ok: false,
			reason: "bad_signature",
			detail: `responder certificate: ${critical.detail}`,
		};
	}

	// The responder certificate is the one key an answer introduces that the
	// path pass never saw, so it is held to the policy the path was —
	// signature algorithm and RSA modulus alike. Last, once the checks above
	// have established it really is this CA's delegate: a stranger's
	// certificate is refused as not issued, whatever it was signed with, and
	// only the CA's own material is remembered under this reason (#470).
	const algorithm = checkAlgorithmPolicy(
		toNode(candidate),
		candidate.signatureAlgorithm.algorithmId,
		algorithms,
	);
	if (!algorithm.ok) {
		return {
			ok: false,
			reason: "algorithm_not_permitted",
			detail: `responder certificate: ${algorithm.detail}`,
		};
	}

	// `id-pkix-ocsp-nocheck` (§4.2.2.2.1) is honoured by construction: the
	// responder certificate's own revocation status is not looked up either
	// way. See the module header.
	return { ok: true };
};

/** The certificate whose key must have signed `basic`: the CA, or a responder it delegated to. */
const identifySigner = async (
	basic: pkijs.BasicOCSPResponse,
	issuer: pkijs.Certificate,
	now: Date,
	crypto: pkijs.ICryptoEngine,
	algorithms: AlgorithmPolicy,
): Promise<{ ok: true; signer: pkijs.Certificate } | SignerRefusal> => {
	const responderId: unknown = basic.tbsResponseData.responderID;
	if (await isNamedResponder(issuer, responderId, crypto)) return { ok: true, signer: issuer };
	for (const candidate of basic.certs ?? []) {
		if (!(await isNamedResponder(candidate, responderId, crypto))) continue;
		const delegated = await checkDelegatedResponder(candidate, issuer, now, crypto, algorithms);
		return delegated.ok ? { ok: true, signer: candidate } : delegated;
	}
	return {
		ok: false,
		reason: "bad_signature",
		detail:
			"the response names a responder that is neither the issuing CA nor a certificate " +
			"attached to the response",
	};
};

const verifySignature = async (
	basic: pkijs.BasicOCSPResponse,
	signer: pkijs.Certificate,
	crypto: pkijs.ICryptoEngine,
): Promise<{ ok: true } | { ok: false; detail: string }> => {
	let verified = false;
	try {
		verified = await crypto.verifyWithPublicKey(
			basic.tbsResponseData.tbsView,
			basic.signature,
			signer.subjectPublicKeyInfo,
			basic.signatureAlgorithm,
		);
	} catch (err) {
		return { ok: false, detail: `signature check failed: ${describeError(err)}` };
	}
	return verified
		? { ok: true }
		: { ok: false, detail: "signature does not verify against the responder's key" };
};

type DecodedStatus =
	| { readonly ok: true; readonly status: OcspCertificateStatus | "unknown" }
	| { readonly ok: false; readonly detail: string };

/** `CertStatus ::= CHOICE { good [0], revoked [1] RevokedInfo, unknown [2] }` (RFC 6960 §4.2.1). */
const decodeStatus = (certStatus: unknown): DecodedStatus => {
	if (!(certStatus instanceof asn1js.BaseBlock) || certStatus.idBlock.tagClass !== 3) {
		return { ok: false, detail: "certStatus is not a context-specific CHOICE" };
	}
	switch (certStatus.idBlock.tagNumber) {
		case 0:
			return { ok: true, status: { status: "good" } };
		case 2:
			return { ok: true, status: "unknown" };
		case 1: {
			const values = certStatus instanceof asn1js.Constructed ? certStatus.valueBlock.value : [];
			const time = values[0];
			if (!(time instanceof asn1js.GeneralizedTime)) {
				return { ok: false, detail: "RevokedInfo carries no revocationTime" };
			}
			let reason: string | undefined;
			const reasonBlock = values[1];
			if (reasonBlock instanceof asn1js.Constructed && reasonBlock.idBlock.tagNumber === 0) {
				const enumerated = reasonBlock.valueBlock.value[0];
				if (enumerated instanceof asn1js.Enumerated) {
					const code = enumerated.valueBlock.valueDec;
					reason = CRL_REASON_NAMES[code] ?? `reason ${code}`;
				}
			}
			return { ok: true, status: { status: "revoked", revokedAt: time.toDate(), reason } };
		}
		default:
			return {
				ok: false,
				detail: `certStatus tag [${certStatus.idBlock.tagNumber}] is not good, revoked or unknown`,
			};
	}
};

type Freshness =
	| { readonly ok: true; readonly expiresAt: number }
	| { readonly ok: false; readonly reason: "not_yet_valid" | "stale"; readonly detail: string };

const freshness = (single: pkijs.SingleResponse, now: Date, cacheTtlSeconds: number): Freshness => {
	const thisUpdate = single.thisUpdate.getTime();
	if (thisUpdate > now.getTime() + OCSP_CLOCK_SKEW_MS) {
		return {
			ok: false,
			reason: "not_yet_valid",
			detail: `the response's thisUpdate ${single.thisUpdate.toISOString()} is in the future`,
		};
	}
	const nextUpdate = single.nextUpdate?.getTime();
	const usableUntil = nextUpdate ?? thisUpdate + OCSP_UNDATED_RESPONSE_MAX_AGE_MS;
	if (usableUntil <= now.getTime()) {
		return {
			ok: false,
			reason: "stale",
			detail:
				nextUpdate === undefined
					? `the response carries no nextUpdate and its thisUpdate ${single.thisUpdate.toISOString()} ` +
						`is older than ${OCSP_UNDATED_RESPONSE_MAX_AGE_MS / 1000}s (RFC 6960 §4.2.2.1)`
					: `the response's nextUpdate ${new Date(nextUpdate).toISOString()} has passed`,
		};
	}
	return { ok: true, expiresAt: Math.min(usableUntil, now.getTime() + cacheTtlSeconds * 1000) };
};

const statusKey = (url: string, issuerId: string, serial: string): string =>
	`ocsp:${url}\n${issuerId}\n${serial}`;
const responderDownKey = (url: string): string => `down:${url}`;
const certificateDownKey = (url: string, issuerId: string, serial: string): string =>
	`down:${url}\n${issuerId}\n${serial}`;

export const createOcspResolver = (options: OcspResolverOptions): OcspResolver => {
	const cache = new Map<string, CacheEntry>();
	const maxEntries = options.maxCacheEntries ?? DEFAULT_MAX_CACHE_ENTRIES;
	const requireNonce = options.requireNonce ?? true;
	/** Requests in progress, so concurrent misses on one certificate issue one request. */
	const inFlight = new Map<string, Promise<Answer>>();

	const store = (key: string, entry: CacheEntry): void => {
		if (cache.size >= maxEntries && !cache.has(key)) {
			// Oldest insertion first, as in `crl.mts`: the bound exists so the
			// map cannot grow without limit, not to maximise hits.
			const oldest = cache.keys().next();
			if (!oldest.done) cache.delete(oldest.value);
		}
		cache.set(key, entry);
	};

	const remember = (
		key: string,
		reason: RespondersFailure | CertificateFailure,
		detail: string,
		now: Date,
	): void =>
		store(key, {
			kind: "unavailable",
			reason,
			detail,
			expiresAt: now.getTime() + OCSP_NEGATIVE_CACHE_TTL_MS,
		});

	/** Ask `url` about `certificate` and judge the answer. Everything the nonce binds happens here. */
	const query = async (
		url: string,
		certificate: pkijs.Certificate,
		issuer: pkijs.Certificate,
		now: Date,
	): Promise<Answer> => {
		const crypto = pkijs.getCrypto(true);
		const request = await buildRequest(certificate, issuer, crypto);
		const fetched = await options.fetch(url, {
			method: "POST",
			body: request.der,
			contentType: OCSP_REQUEST_MEDIA_TYPE,
			accept: OCSP_RESPONSE_MEDIA_TYPE,
			expectContentType: OCSP_RESPONSE_MEDIA_TYPE,
		});
		if (!fetched.ok) {
			return { ok: false, reason: "fetch_failed", detail: `${fetched.reason} (${fetched.detail})` };
		}

		const parsed = parseResponse(fetched.bytes);
		if (!parsed.ok) return parsed;
		const basic = parsed.basic;

		// Shape before signature, as in `crl.mts`: nothing an unverified
		// response *says* is acted on here, only what it is shaped like, and
		// the answer is at most "do not use it".
		const single = await findSingleResponse(basic, certificate, issuer, request.certId, crypto);
		if (single === undefined) {
			return {
				ok: false,
				reason: "no_matching_response",
				detail: "the response carries no single response for this certificate's CertID",
			};
		}
		const critical = checkOcspCriticalExtensions(
			basic.tbsResponseData.responseExtensions ?? [],
			single.singleExtensions ?? [],
		);
		if (!critical.ok) {
			return { ok: false, reason: "unsupported_critical_extension", detail: critical.detail };
		}

		// The response's own signature algorithm, still on shape alone: the
		// OID it names is judged before its signer is even identified, and
		// remembered per certificate like the check above (see the module
		// header, #470). The responder certificate, when there is one, is
		// held to the full policy inside `identifySigner`.
		const algorithm = checkSignatureAlgorithm(
			basic.signatureAlgorithm.algorithmId,
			options.algorithms,
		);
		if (!algorithm.ok) {
			return {
				ok: false,
				reason: "algorithm_not_permitted",
				detail: `the response's signature algorithm ${algorithm.detail}`,
			};
		}

		const signer = await identifySigner(basic, issuer, now, crypto, options.algorithms);
		if (!signer.ok) return { ok: false, reason: signer.reason, detail: signer.detail };
		const signature = await verifySignature(basic, signer.signer, crypto);
		if (!signature.ok) return { ok: false, reason: "bad_signature", detail: signature.detail };

		// The nonce is judged on bytes the responder actually signed.
		const echoed = basic.tbsResponseData.responseExtensions?.find(
			(ext) => ext.extnID === OID_OCSP_NONCE,
		);
		if (echoed === undefined) {
			if (requireNonce) {
				return {
					ok: false,
					reason: "nonce_missing",
					detail:
						"the response carries no nonce, so nothing binds it to this request " +
						"(RFC 6960 §4.4.1; set ocsp-require-nonce = false only for a responder " +
						"that pre-produces its answers)",
				};
			}
		} else if (!equalBytes(echoed.extnValue.valueBlock.valueHexView, request.nonce)) {
			return {
				ok: false,
				reason: "nonce_mismatch",
				detail: "the response's nonce is not the one this request sent",
			};
		}

		const decoded = decodeStatus(single.certStatus);
		if (!decoded.ok) return { ok: false, reason: "unparseable", detail: decoded.detail };

		const fresh = freshness(single, now, options.cacheTtlSeconds);
		if (!fresh.ok) return fresh;

		if (decoded.status === "unknown") {
			return {
				ok: false,
				reason: "unknown",
				detail: `the responder at ${url} does not know the certificate (RFC 6960 §2.2)`,
			};
		}
		return { ok: true, status: decoded.status, expiresAt: fresh.expiresAt };
	};

	/** `query`, joining a request for the same certificate that is already in flight. */
	const load = (
		key: string,
		url: string,
		certificate: pkijs.Certificate,
		issuer: pkijs.Certificate,
		now: Date,
	): Promise<Answer> => {
		const existing = inFlight.get(key);
		if (existing !== undefined) return existing;
		const pending = query(url, certificate, issuer, now).finally(() => inFlight.delete(key));
		inFlight.set(key, pending);
		return pending;
	};

	/** What `url` says about `certificate` — from the cache, or by asking now. */
	const lookup = async (
		url: string,
		certificate: pkijs.Certificate,
		issuer: pkijs.Certificate,
		issuerId: string,
		serial: string,
		now: Date,
	): Promise<Answer> => {
		const known = cache.get(statusKey(url, issuerId, serial));
		if (known?.kind === "status" && known.expiresAt > now.getTime()) {
			return { ok: true, status: known.status, expiresAt: known.expiresAt };
		}
		for (const key of [responderDownKey(url), certificateDownKey(url, issuerId, serial)]) {
			const down = cache.get(key);
			if (down?.kind === "unavailable" && down.expiresAt > now.getTime()) {
				return { ok: false, reason: down.reason, detail: `${down.detail}; not retried yet` };
			}
		}

		const answer = await load(`${url}\n${issuerId}\n${serial}`, url, certificate, issuer, now);
		if (answer.ok) {
			store(statusKey(url, issuerId, serial), {
				kind: "status",
				status: answer.status,
				expiresAt: answer.expiresAt,
			});
			return answer;
		}
		if (RESPONDER_FAILURES.has(answer.reason)) {
			remember(responderDownKey(url), answer.reason as RespondersFailure, answer.detail, now);
		} else if (CERTIFICATE_FAILURES.has(answer.reason)) {
			remember(
				certificateDownKey(url, issuerId, serial),
				answer.reason as CertificateFailure,
				answer.detail,
				now,
			);
		}
		// `bad_signature` and `nonce_mismatch` are left unremembered on purpose.
		return answer;
	};

	return {
		size: () => cache.size,

		resolve: async (certificate, issuer, now) => {
			const responders = ocspResponders(certificate);
			if (!responders.ok) return responders;

			const issuerId = issuerKeyId(issuer);
			const serial = serialHex(certificate);
			const failures: { url: string; reason: OcspUnavailableReason; detail: string }[] = [];
			for (const url of responders.urls) {
				const answer = await lookup(url, certificate, issuer, issuerId, serial, now);
				if (answer.ok) return { ok: true, responder: url, status: answer.status };
				failures.push({ url, reason: answer.reason, detail: answer.detail });
			}
			const last = failures[failures.length - 1];
			return {
				ok: false,
				reason: last?.reason ?? "fetch_failed",
				detail: failures
					.map((entry) => `${entry.url}: ${entry.reason} (${entry.detail})`)
					.join("; "),
			};
		},
	};
};
