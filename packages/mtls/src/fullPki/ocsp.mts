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
 * `mode = "full-pki"`. `pkijs` only encodes the request and decodes the
 * response; asking the responder (a POST under `fetchGuard.mts`), verifying
 * who signed the answer, matching the nonce, judging freshness and caching
 * happen here.
 *
 * Always a responder fetch: Node exposes no stapled response for a client
 * certificate, so a certificate demanding must-staple (RFC 7633) is refused
 * by `checkMustStaple`.
 *
 * The answer is verified here, not by pkijs: `BasicOCSPResponse.verify`
 * ignores `id-kp-OCSPSigning` (any certificate the CA issued could vouch for
 * itself), and `getCertificateStatus` answers `unknown` for a response about
 * another certificate. Per RFC 6960 §4.2.2.2 a response is believed only when
 * signed by the issuing CA, or by a certificate that CA issued which carries
 * `id-kp-OCSPSigning`, is within its validity, has no unprocessed critical
 * extension, and meets the path's algorithm policy. A delegated responder
 * without `id-pkix-ocsp-nocheck` (§4.2.2.2.1) is itself checked through
 * `responderRevocation` (the CRL arm under `mode = "both"`) on every use,
 * cache hits included; with no source to check it, the answer is taken and
 * flagged `responderUnchecked` — the local-policy deviation the README states.
 *
 * - As in `crl.mts`, shape checks (the matching `CertID`, critical
 *   extensions, the response's signature algorithm — pkijs accepts SHA-1)
 *   run before the signature, can only refuse, and so are remembered.
 * - The `CertID` hash is SHA-1 (§4.1.1): a lookup key, not a signature, and
 *   the one responders reliably answer. Another hash in a response is matched
 *   by recomputing.
 * - Every request carries a 16-byte nonce (§4.4.1, RFC 8954). A different
 *   echo is refused; a missing one too unless `requireNonce: false` (a
 *   pre-producing responder), since otherwise a "good" captured before a
 *   revocation replays until its `nextUpdate`.
 * - `unknown` (§2.2) is unavailable, not good: a responder that lost its
 *   database must not un-revoke everything.
 * - Caching is keyed per certificate: concurrent lookups share a request;
 *   answers live until `nextUpdate` or `cache-ttl-seconds`; failures are
 *   remembered for `OCSP_NEGATIVE_CACHE_TTL_MS` per responder (transport or
 *   responder-level) or per certificate (an unusable answer); `bad_signature`
 *   and `nonce_mismatch` are never remembered.
 * - Unavailabilities carry `reason`, `detail` and `cause` as in `crl.mts`,
 *   and are an `outage` when the responder did not answer usefully
 *   (`isSourceFailure`, `unparseable`, `responder_error`, `stale`, or a
 *   delegated responder's status unreadable for such a reason).
 */

import { createHash, X509Certificate } from "node:crypto";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
	type AlgorithmPolicy,
	checkAlgorithmPolicy,
	checkSignatureAlgorithm,
} from "./algorithms.mjs";
import {
	checkCriticalExtensions,
	checkOcspCriticalExtensions,
	extensionValueParsed,
} from "./criticalExtensions.mjs";
import { CRL_NEGATIVE_CACHE_TTL_MS } from "./crl.mjs";
import { DEFAULT_ALGORITHM_POLICY } from "./defaults.mjs";
import { type GuardedFetch, isSourceFailure } from "./fetchGuard.mjs";
import {
	type Answer,
	markOutage,
	type OcspCertificateStatus,
	type OcspLookup,
	type OcspResponderUnavailable,
	type OcspUnavailableReason,
} from "./ocspAnswer.mjs";
import { equalBytes } from "./ocspBytes.mjs";
import { buildRequest, checkNonce } from "./ocspRequest.mjs";
import { ocspResponders } from "./ocspResponders.mjs";

export type {
	OcspCertificateStatus,
	OcspLookup,
	OcspResponderUnavailable,
	OcspUnavailableReason,
} from "./ocspAnswer.mjs";
export { checkMustStaple } from "./ocspMustStaple.mjs";
export { type OcspResponders, ocspResponders } from "./ocspResponders.mjs";

/** `id-pkix-ocsp-basic` response type (RFC 6960 §4.2.1). */
const OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1";
/** `id-kp-OCSPSigning` (RFC 6960 §4.2.2.2). */
const OID_KP_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";
/** `id-pkix-ocsp-nocheck` (RFC 6960 §4.2.2.2.1): the CA vouches for the responder for its certificate's lifetime. */
const OID_OCSP_NOCHECK = "1.3.6.1.5.5.7.48.1.5";
/** `extendedKeyUsage` (RFC 5280 §4.2.1.12). */
const OID_EXT_KEY_USAGE = "2.5.29.37";
/** SHA-1, the `CertID` hash. */
const OID_SHA1 = "1.3.14.3.2.26";

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

/** Reasons remembered for the negative window, and at which granularity. */
type RespondersFailure =
	| "fetch_failed"
	| "unparseable"
	| "responder_error"
	| "responder_revoked"
	| "responder_status_unavailable";
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
	"responder_revoked",
	"responder_status_unavailable",
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
			/** The delegated responder to re-check before this entry is believed. */
			readonly delegate?: pkijs.Certificate;
	  }
	| {
			readonly kind: "unavailable";
			readonly reason: RespondersFailure | CertificateFailure;
			readonly detail: string;
			readonly cause?: unknown;
			readonly outage?: true;
			/** Epoch millis after which the responder is tried again. */
			readonly expiresAt: number;
	  };

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
	 * certificate too. Defaults to `DEFAULT_ALGORITHM_POLICY`, the strict
	 * policy, so omitting it can only make the check stricter; `validate.mts`
	 * passes the configured policy.
	 */
	readonly algorithms?: AlgorithmPolicy;
	/**
	 * Refuse a response that does not carry the request's nonce. Defaults to
	 * `true`; see the module header for what `false` gives up.
	 */
	readonly requireNonce?: boolean;
	/** Bound on cache size. Entries are per certificate, so the default is roomier than the CRL cache's. */
	readonly maxCacheEntries?: number;
	/**
	 * How a delegated responder's own certificate is checked for revocation
	 * when it lacks `id-pkix-ocsp-nocheck` (RFC 6960 §4.2.2.2.1); `validate.mts`
	 * wires the CRL arm under `mode = "both"`. Absent, or answering
	 * `unspecified`, such a responder's answer is taken and flagged
	 * `responderUnchecked`.
	 */
	readonly responderRevocation?: ResponderRevocationCheck;
}

/** What {@link ResponderRevocationCheck} learned about a delegated responder's certificate. */
export type ResponderRevocationOutcome =
	| { readonly kind: "determined" }
	/** The CA named no source for the responder's certificate (§4.2.2.2.1, third option): local policy decides, which is to take the answer and report `responderUnchecked`. */
	| { readonly kind: "unspecified" }
	| { readonly kind: "revoked"; readonly detail: string }
	| {
			readonly kind: "unavailable";
			readonly reason: string;
			readonly detail: string;
			readonly cause?: unknown;
			/** The source for the responder's status did not answer usefully. */
			readonly outage?: true;
	  };

export type ResponderRevocationCheck = (
	responder: pkijs.Certificate,
	issuer: pkijs.Certificate,
	now: Date,
) => Promise<ResponderRevocationOutcome>;

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

type Parsed =
	| { readonly ok: true; readonly basic: pkijs.BasicOCSPResponse }
	| {
			readonly ok: false;
			readonly reason: "unparseable" | "responder_error";
			readonly detail: string;
			readonly cause?: unknown;
	  };

const parseResponse = (bytes: Uint8Array): Parsed => {
	let response: pkijs.OCSPResponse;
	try {
		response = pkijs.OCSPResponse.fromBER(bytes);
	} catch (err) {
		return {
			ok: false,
			reason: "unparseable",
			detail: "not a DER OCSPResponse",
			cause: err,
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
			detail: "not a DER BasicOCSPResponse",
			cause: err,
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
	// path pass never saw, so it is held to the path's policy (signature
	// algorithm and RSA modulus). Checked last, once it is established as this
	// CA's delegate: a stranger's certificate is refused as not issued, and only
	// the CA's own material is remembered under this reason.
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

	// The responder certificate's own revocation status is the caller's
	// (`checkResponder`), skipped only for one carrying `id-pkix-ocsp-nocheck`.
	return { ok: true };
};

/**
 * Whether a delegated responder's certificate carries `id-pkix-ocsp-nocheck`
 * with the DER `NULL` value RFC 6960 §4.2.2.2.1 specifies. Any other value
 * buys no exemption: it is not a statement the CA wrote.
 */
const hasNoCheck = (certificate: pkijs.Certificate): boolean => {
	const extension = certificate.extensions?.find((ext) => ext.extnID === OID_OCSP_NOCHECK);
	if (extension === undefined) return false;
	const bytes = extension.extnValue.valueBlock.valueHexView;
	return bytes.length === 2 && bytes[0] === 0x05 && bytes[1] === 0x00;
};

/** The certificate whose key must have signed `basic`: the CA, or a responder it delegated to. */
const identifySigner = async (
	basic: pkijs.BasicOCSPResponse,
	issuer: pkijs.Certificate,
	now: Date,
	crypto: pkijs.ICryptoEngine,
	algorithms: AlgorithmPolicy,
): Promise<
	{ ok: true; signer: pkijs.Certificate; delegate?: pkijs.Certificate } | SignerRefusal
> => {
	const responderId: unknown = basic.tbsResponseData.responderID;
	if (await isNamedResponder(issuer, responderId, crypto)) return { ok: true, signer: issuer };
	for (const candidate of basic.certs ?? []) {
		if (!(await isNamedResponder(candidate, responderId, crypto))) continue;
		const delegated = await checkDelegatedResponder(candidate, issuer, now, crypto, algorithms);
		return delegated.ok ? { ok: true, signer: candidate, delegate: candidate } : delegated;
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
): Promise<{ ok: true } | { ok: false; detail: string; cause?: unknown }> => {
	let verified = false;
	try {
		verified = await crypto.verifyWithPublicKey(
			basic.tbsResponseData.tbsView,
			basic.signature,
			signer.subjectPublicKeyInfo,
			basic.signatureAlgorithm,
		);
	} catch (err) {
		// Thrown rather than answered `false`: a signature value WebCrypto
		// cannot read, a key it cannot import. Its text stays on the cause.
		return { ok: false, detail: "signature check failed", cause: err };
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
	const algorithms = options.algorithms ?? DEFAULT_ALGORITHM_POLICY;
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
		failure: { readonly detail: string; readonly cause?: unknown; readonly outage?: true },
		now: Date,
	): void =>
		store(key, {
			kind: "unavailable",
			reason,
			detail: failure.detail,
			...(failure.cause !== undefined ? { cause: failure.cause } : {}),
			...(failure.outage ? { outage: true } : {}),
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
			return {
				ok: false,
				reason: "fetch_failed",
				detail: `${fetched.reason} (${fetched.detail})`,
				...(fetched.cause !== undefined ? { cause: fetched.cause } : {}),
				...(isSourceFailure(fetched.reason) ? { outage: true } : {}),
			};
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

		// The response's own signature algorithm, still on shape alone, judged
		// before its signer is identified and remembered per certificate (see
		// the module header). A responder certificate is held to the full
		// policy inside `identifySigner`.
		const algorithm = checkSignatureAlgorithm(basic.signatureAlgorithm.algorithmId, algorithms);
		if (!algorithm.ok) {
			return {
				ok: false,
				reason: "algorithm_not_permitted",
				detail: `the response's signature algorithm ${algorithm.detail}`,
			};
		}

		const signer = await identifySigner(basic, issuer, now, crypto, algorithms);
		if (!signer.ok) return { ok: false, reason: signer.reason, detail: signer.detail };
		const signature = await verifySignature(basic, signer.signer, crypto);
		if (!signature.ok) {
			return {
				ok: false,
				reason: "bad_signature",
				detail: signature.detail,
				...(signature.cause !== undefined ? { cause: signature.cause } : {}),
			};
		}
		// The delegated responder's own certificate, checked here and again
		// whenever this answer is served from the cache.
		const delegate =
			signer.delegate !== undefined && !hasNoCheck(signer.delegate) ? signer.delegate : undefined;
		let responderUnchecked = false;
		if (delegate !== undefined) {
			const verdict = await checkResponder(delegate, issuer, now);
			if (!verdict.ok) return verdict;
			responderUnchecked = verdict.unchecked;
		}

		// The nonce is judged on bytes the responder actually signed.
		const nonce = checkNonce(basic, request.nonce, requireNonce);
		if (!nonce.ok) return nonce;

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
		return {
			ok: true,
			responderUnchecked,
			status: decoded.status,
			expiresAt: fresh.expiresAt,
			...(delegate === undefined ? {} : { delegate }),
		};
	};

	/**
	 * A delegated responder's own certificate. RFC 6960 §4.2.2.2.1 lets a
	 * client skip this only for a responder carrying `id-pkix-ocsp-nocheck`;
	 * otherwise it is checked through the source the caller wired — the CA's
	 * CRL, which the responder cannot answer for itself. A revoked responder's
	 * `good` is worth nothing. With no source wired, or none the CA named, the
	 * answer is taken and the deviation reported. Called when the answer is
	 * built and on every cache hit, since the cached status outlives the check.
	 */
	const checkResponder = async (
		delegate: pkijs.Certificate,
		issuer: pkijs.Certificate,
		now: Date,
	): Promise<
		| { ok: true; unchecked: boolean }
		| {
				ok: false;
				reason: OcspUnavailableReason;
				detail: string;
				cause?: unknown;
				outage?: true;
		  }
	> => {
		if (options.responderRevocation === undefined) return { ok: true, unchecked: true };
		const own = await options.responderRevocation(delegate, issuer, now);
		if (own.kind === "revoked") {
			return {
				ok: false,
				reason: "responder_revoked",
				detail: `the delegated responder's certificate is revoked: ${own.detail}`,
			};
		}
		if (own.kind === "unavailable") {
			return {
				ok: false,
				reason: "responder_status_unavailable",
				detail:
					"the delegated responder's own revocation status is unavailable " +
					`(${own.reason}): ${own.detail}`,
				...(own.cause !== undefined ? { cause: own.cause } : {}),
				...(own.outage ? { outage: true } : {}),
			};
		}
		return { ok: true, unchecked: own.kind === "unspecified" };
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
		const pending = query(url, certificate, issuer, now)
			.then(markOutage)
			.finally(() => inFlight.delete(key));
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
		const statusCacheKey = statusKey(url, issuerId, serial);
		const known = cache.get(statusCacheKey);
		if (known?.kind === "status" && known.expiresAt > now.getTime()) {
			// A cached answer from a delegated responder is only as good as that
			// responder still is: re-check it (the source behind the hook caches,
			// so this is cheap) and drop the entry if it has been revoked since.
			if (known.delegate !== undefined) {
				const verdict = await checkResponder(known.delegate, issuer, now);
				if (!verdict.ok) {
					cache.delete(statusCacheKey);
					return verdict;
				}
				return {
					ok: true,
					status: known.status,
					expiresAt: known.expiresAt,
					responderUnchecked: verdict.unchecked,
					delegate: known.delegate,
				};
			}
			return { ok: true, status: known.status, expiresAt: known.expiresAt };
		}
		for (const key of [responderDownKey(url), certificateDownKey(url, issuerId, serial)]) {
			const down = cache.get(key);
			if (down?.kind === "unavailable" && down.expiresAt > now.getTime()) {
				return {
					ok: false,
					reason: down.reason,
					detail: `${down.detail}; not retried yet`,
					...(down.cause !== undefined ? { cause: down.cause } : {}),
					...(down.outage ? { outage: true } : {}),
				};
			}
		}

		const answer = await load(`${url}\n${issuerId}\n${serial}`, url, certificate, issuer, now);
		if (answer.ok) {
			store(statusCacheKey, {
				kind: "status",
				status: answer.status,
				expiresAt: answer.expiresAt,
				...(answer.delegate === undefined ? {} : { delegate: answer.delegate }),
			});
			return answer;
		}
		if (RESPONDER_FAILURES.has(answer.reason)) {
			remember(responderDownKey(url), answer.reason as RespondersFailure, answer, now);
		} else if (CERTIFICATE_FAILURES.has(answer.reason)) {
			remember(
				certificateDownKey(url, issuerId, serial),
				answer.reason as CertificateFailure,
				answer,
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
			const failures: OcspResponderUnavailable[] = [];
			for (const url of responders.urls) {
				const answer = await lookup(url, certificate, issuer, issuerId, serial, now);
				if (answer.ok) {
					return {
						ok: true,
						responder: url,
						status: answer.status,
						...(answer.responderUnchecked ? { responderUnchecked: true } : {}),
					};
				}
				failures.push({
					url,
					reason: answer.reason,
					detail: answer.detail,
					...(answer.cause !== undefined ? { cause: answer.cause } : {}),
					...(answer.outage ? { outage: true } : {}),
				});
			}
			const last = failures[failures.length - 1];
			return {
				ok: false,
				reason: last?.reason ?? "fetch_failed",
				detail: failures
					.map((entry) => `${entry.url}: ${entry.reason} (${entry.detail})`)
					.join("; "),
				...(last?.cause !== undefined ? { cause: last.cause } : {}),
				...(failures.length > 0 && failures.every((entry) => entry.outage) ? { outage: true } : {}),
				responders: failures,
			};
		},
	};
};
